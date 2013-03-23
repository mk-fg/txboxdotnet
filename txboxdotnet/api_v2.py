#-*- coding: utf-8 -*-

import itertools as it, operator as op, functools as ft
from urllib import urlencode
from mimetypes import guess_type
from time import time
from collections import Mapping, OrderedDict
from datetime import datetime, timedelta
from os.path import join, basename
import os, sys, io, re, types, weakref, logging
import urllib, urlparse, json

from OpenSSL import crypto
from zope.interface import implements

from twisted.web.iweb import IBodyProducer, UNKNOWN_LENGTH
from twisted.web.http_headers import Headers
from twisted.web import http
from twisted.internet import defer, reactor, ssl, task, protocol
from twisted.internet.error import TimeoutError

from twisted.web.client import Agent, RedirectAgent,\
	HTTPConnectionPool, HTTP11ClientProtocol, ContentDecoderAgent, GzipDecoder
from twisted.web.client import ResponseDone,\
	ResponseFailed, RequestNotSent, RequestTransmissionFailed

try: # doesn't seem to be a part of public api
	from twisted.web._newclient import RequestGenerationFailed
except ImportError: # won't be handled
	class RequestGenerationFailed(Exception): pass



class BoxInteractionError(Exception): pass

class APILimitationError(BoxInteractionError): pass

class ProtocolError(BoxInteractionError):
	def __init__(self, code, msg):
		super(ProtocolError, self).__init__(code, msg)
		self.code = code

class AuthenticationError(BoxInteractionError): pass

class DoesNotExists(BoxInteractionError):
	'Only raised from BoxAPI.resolve_path().'



from twisted.python import log as twisted_log

class log(object): pass # proxy object, emulating python logger
for lvl in 'debug', 'info', ('warning', 'warn'), 'error', ('critical', 'fatal'):
	lvl, func = lvl if isinstance(lvl, tuple) else (lvl, lvl)
	setattr(log, func, staticmethod(ft.partial(
		twisted_log.msg, logLevel=logging.getLevelName(lvl.upper()) )))

try: import anyjson as json
except ImportError:
	try: import simplejson as json
	except ImportError: import json



class BoxAuthMixin(object):

	#: Client id/secret should be static on per-application basis.
	#: Can be received from box.com by any registered user at http://www.box.net/developers/services
	#: API ToS can be found at https://www.box.com/static/html/terms.html
	#: API Auth docs: http://developers.box.com/oauth/
	client_id = client_secret = None

	auth_url_user = 'https://www.box.com/api/oauth2/authorize'
	auth_url_token = 'https://www.box.com/api/oauth2/token'

	#: auth_redirect_uri should be any https url, and it has to be non-malicious.
	#: Neither localhost nor any random "example.com" urls satisfy that,
	#:  so I assume here that box.com won't steal it's own access credentials.
	#: If module is used in webapp - override this parameter with your webapp url.
	#: Might be overidden in box.com app settings.
	auth_redirect_uri = 'https://success.box.com/'

	#: Set by auth_get_token() method, not used internally.
	#: Might be useful for debugging or extension purposes.
	auth_access_expires = auth_access_data_raw = None

	#: At least one of auth_code, auth_refresh_token or
	#:  auth_access_token should be set before data requests.
	auth_code = auth_refresh_token = auth_access_token = None

	#: "state=" passed to API on first oauth2 request - "an arbitrary string of your choosing"
	auth_state_check = 'boxed'


	def __init__(self, **config):
		'Initialize API wrapper class with specified properties set.'
		for k, v in config.viewitems():
			try: getattr(self, k)
			except AttributeError:
				raise AttributeError('Unrecognized configuration key: {}'.format(k))
			setattr(self, k, v)


	def auth_user_get_url(self):
		'Build authorization URL for User Agent.'
		if not self.client_id: raise AuthenticationError('No client_id specified')
		return '{}?{}'.format(self.auth_url_user, urllib.urlencode(dict(
			client_id=self.client_id, state=self.auth_state_check,
			response_type='code', redirect_uri=self.auth_redirect_uri )))

	def auth_user_process_url(self, url):
		'Process tokens and errors from redirect_uri.'
		url = urlparse.urlparse(url)
		url_qs = dict(it.chain.from_iterable(
			urlparse.parse_qsl(v) for v in [url.query, url.fragment] ))
		if url_qs.get('error'):
			raise AuthenticationError('{} :: {}'.format(
				url_qs['error'], url_qs.get('error_description') ))
		self.auth_code = url_qs['code']
		return self.auth_code


	def auth_get_token(self, check_state=True):
		'Refresh or acquire access_token.'
		res = self.auth_access_data_raw = self._auth_token_request()
		return self._auth_token_process(res, check_state=check_state)

	def _auth_token_request(self):
		post_data = dict( client_id=self.client_id,
			client_secret=self.client_secret, redirect_uri=self.auth_redirect_uri )
		if not self.auth_refresh_token:
			log.debug('Requesting new access_token through authorization_code grant')
			post_data.update(code=self.auth_code, grant_type='authorization_code')
		else:
			log.debug('Refreshing access_token')
			post_data.update(
				refresh_token=self.auth_refresh_token, grant_type='refresh_token' )
		post_data_missing_keys = list(k for k in
			['client_id', 'client_secret', 'code', 'refresh_token', 'grant_type']
			if k in post_data and not post_data[k])
		if post_data_missing_keys:
			raise AuthenticationError( 'Insufficient authentication'
				' data provided (missing keys: {})'.format(post_data_missing_keys) )

		return self.request(self.auth_url_token, method='post', data=post_data)

	def _auth_token_process(self, res, check_state=True):
		assert res['token_type'] == 'bearer'
		for k in 'access_token', 'refresh_token':
			if k in res: setattr(self, 'auth_{}'.format(k), res[k])
		self.auth_access_expires = None if 'expires_in' not in res\
			else (datetime.utcnow() + timedelta(0, res['expires_in']))

		state_returned = res.get('state', '') # might be missing if clever user pasted only the code
		if state_returned and check_state and self.auth_state_check != state_returned:
			raise AuthenticationError(
				"Returned URL state ({}) doesn't match requested one ({})."\
					.format(state_returned, self.auth_state_check) )



class BoxAPIWrapper(BoxAuthMixin):
	'''Less-biased Box API wrapper class.
		All calls made here return result of self.request() call directly,
			so it can easily be made async (e.g. return twisted deferred object)
			by overriding http request method in subclass.'''
	# API docs: http://developers.box.com/docs/

	#: URL of the main API, used for most operations
	api_url_base = 'https://api.box.com/2.0/'

	#: Box uses a separate URL for upload ops
	#: Can be empty to use generic api_url_base
	api_url_upload = 'https://upload.box.com/2.0/'

	def _api_url( self, path, query=dict(), upload=False,
			pass_access_token=True, pass_empty_values=False ):
		query = query.copy()
		if pass_access_token:
			query.setdefault('access_token', self.auth_access_token)
		if not pass_empty_values:
			for k, v in query.viewitems():
				if not v:
					raise AuthenticationError('Empty key {!r} for API call (path: {})'.format(k, path))
		api_url = self.api_url_base
		if upload and self.api_url_upload: api_url = self.api_url_upload
		return urlparse.urljoin( api_url,
			'{}?{}'.format(path, urllib.urlencode(query)) )

	def __call__( self, url, query=dict(),
			query_filter=True, auth_header=False,
			auto_refresh_token=True, upload=False, **request_kwz ):
		'''Make an arbitrary call to Box API.
			Shouldn't be used directly under most circumstances.'''
		if query_filter:
			query = dict((k, v) for k, v in
				query.viewitems() if v is not None)
		if auth_header:
			request_kwz.setdefault('headers', dict())\
				['Authorization'] = 'Bearer {}'.format(self.auth_access_token)
		kwz = request_kwz.copy()
		kwz.setdefault('raise_for', dict())[401] = AuthenticationError
		api_url = ft.partial( self._api_url, url, query,
			pass_access_token=not auth_header, upload=upload )
		try: return self.request(api_url(), **kwz)
		except AuthenticationError:
			if not auto_refresh_token: raise
			self.auth_get_token()
			if auth_header: # update auth header with a new token
				request_kwz['headers']['Authorization']\
					= 'Bearer {}'.format(self.auth_access_token)
			return self.request(api_url(), **request_kwz)

	def listdir(self, folder_id='0', offset=None, limit=None):
		'Get Box object, representing list of objects in a folder.'
		return self(join('folders', folder_id, 'items'), dict(offset=offset, limit=limit))

	def get_user_info(self):
		'Get Box object, representing user, containing quota info (among other info).'
		return self('users/me')



class UnderlyingProtocolError(ProtocolError):
	'Raised for e.g. ResponseFailed non-HTTP errors from HTTP client.'

	def __init__(self, err):
		# Set http-503, to allow handling of it similar way for http-oriented code
		super(UnderlyingProtocolError, self)\
			.__init__(http.SERVICE_UNAVAILABLE, err.message)
		self.error = err



class DataReceiver(protocol.Protocol):

	def __init__(self, done, timer=None):
		self.done, self.timer, self.data = done, timer, list()

	def dataReceived(self, chunk):
		if self.timer:
			if not self.data: self.timer.state_next('res_body') # first chunk
			else:
				try: self.timer.timeout_reset()
				except self.timer.TooLate as err:
					self.done.errback(err)
					self.timer = self.data = None
		if self.data is not None: self.data.append(chunk)

	def connectionLost(self, reason):
		if self.timer: self.timer.state_next()
		if not isinstance(reason.value, ResponseDone): # some error
			self.done.callback(reason)
		elif not self.done.called: # might errback due to timer
			self.done.callback(
				b''.join(self.data) if self.data is not None else b'' )



class FileBodyProducer(object):
	implements(IBodyProducer)

	_task = None

	#: Single read/write size
	chunk_size = 64 * 2**10 # 64 KiB

	def __init__(self, src, timer=None):
		self.src, self.timer = src, timer

		# Set length, if possible
		try: src.seek, src.tell
		except AttributeError: self.length = UNKNOWN_LENGTH
		else:
			pos = src.tell()
			try:
				src.seek(0, os.SEEK_END)
				self.length = src.tell() - pos
			finally: src.seek(pos)

	@defer.inlineCallbacks
	def upload_file(self, src, dst):
		try:
			while True:
				if self.timer:
					try: self.timer.timeout_reset()
					except self.timer.TooLate as err:
						self.timer = None
						break
				chunk = src.read(self.chunk_size)
				if not chunk: break
				yield dst.write(chunk)
		finally: src.close()

	@defer.inlineCallbacks
	def send(self, dst):
		res = yield self.upload_file(self.src, dst)
		if self.timer: self.timer.state_next()
		defer.returnValue(res)

	def startProducing(self, dst):
		if self.timer: self.timer.state_next('req_body')
		if not self._task: self._task = self.send(dst)
		return self._task

	def resumeProducing(self):
		if not self._task: return
		self._task.unpause()

	def pauseProducing(self):
		if not self._task: return
		self._task.pause()

	def stopProducing(self):
		if not self._task: return
		self._task.cancel()
		self._task = None


class MultipartDataSender(FileBodyProducer):

	def __init__(self, fields, boundary, timer=None):
		self.fields, self.boundary, self.timer = fields, boundary, timer

		# "Transfer-Encoding: chunked" doesn't work with SkyDrive,
		#  so calculate_length() must be called to replace it with some value
		# TODO: test "chunked" with box - it's no skydrive
		self.length = UNKNOWN_LENGTH

	def calculate_length(self):
		d = self.send()
		d.addCallback(lambda length: setattr(self, 'length', length))
		return d

	@defer.inlineCallbacks
	def send(self, dst=None):
		dry_run = not dst
		if dry_run: dst, dst_ext = io.BytesIO(), 0

		for name, data in self.fields.viewitems():
			dst.write(b'--{}\r\n'.format(self.boundary))

			if isinstance(data, tuple):
				fn, data = data
				ct = guess_type(fn)[0] or b'application/octet-stream'
				dst.write(
					b'Content-Disposition: form-data;'
					b' name="{}"; filename="{}"\r\n'.format(name, fn) )
			else:
				ct = b'text/plain'
				dst.write( b'Content-Disposition:'
					b' form-data; name="{}"\r\n'.format(name) )
			dst.write(b'Content-Type: {}\r\n\r\n'.format(ct))

			if isinstance(data, types.StringTypes): dst.write(data)
			elif not dry_run: yield self.upload_file(data, dst)
			else: dst_ext += os.fstat(data.fileno()).st_size
			dst.write(b'\r\n')

		dst.write(b'--{}--\r\n'.format(self.boundary))

		if dry_run: defer.returnValue(dst_ext + len(dst.getvalue()))
		else:
			self._task = None
			if self.timer: self.timer.state_next()



class TLSContextFactory(ssl.CertificateOptions):

	isClient = 1

	def __init__(self, ca_certs_files):
		ca_certs = dict()

		for ca_certs_file in ( [ca_certs_files]
				if isinstance(ca_certs_files, types.StringTypes) else ca_certs_files ):
			with open(ca_certs_file) as ca_certs_file:
				ca_certs_file = ca_certs_file.read()
			for cert in re.findall( r'(-----BEGIN CERTIFICATE-----'
					r'.*?-----END CERTIFICATE-----)', ca_certs_file, re.DOTALL ):
				cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
				ca_certs[cert.digest('sha1')] = cert

		super(TLSContextFactory, self).__init__(verify=True, caCerts=ca_certs.values())

	def getContext(self, hostname, port):
		return super(TLSContextFactory, self).getContext()


class QuietHTTP11ClientFactory(protocol.Factory):

	noisy = False
	protocol = HTTP11ClientProtocol

	def __init__(self, quiescentCallback):
		self._quiescentCallback = quiescentCallback

	def buildProtocol(self, addr):
		return self.protocol(self._quiescentCallback)


class QuietHTTPConnectionPool(HTTPConnectionPool):

	_factory = QuietHTTP11ClientFactory

	def __init__(self, reactor, persistent=True, debug_requests=False, **pool_kwz):
		super(QuietHTTPConnectionPool, self).__init__(reactor, persistent=persistent)
		for k, v in pool_kwz.viewitems():
			getattr(self, k) # to somewhat protect against typos
			setattr(self, k, v)



class HTTPTimeout(defer.Deferred, object):

	'''Deferred that will errback if timeout_reset() won't be called in time.
		What "in time" means depends on current state and state_timeouts.
		States can be switched by state_next() method.
		Callback is invoked when the last state is passed or on state_finished() call.'''

	class ActivityTimeout(Exception): pass
	class TooLate(Exception): pass

	_state = _timeout = None
	state_timeouts = OrderedDict([ ('req_headers', 60),
		('req_body', 20), ('res_headers', 20), ('res_body', 20), ('res_end', 10) ])

	def __init__(self, timeouts=None, **state_timeouts):
		if timeouts:
			assert not state_timeouts
			self.state_timeouts = timeouts
		elif state_timeouts:
			for k, v in state_timeouts.viewitems():
				assert k in self.state_timeouts, k
				self.state_timeouts[k] = v
		super(HTTPTimeout, self).__init__()
		self._state = next(iter(self.state_timeouts))
		self.timeout_reset()

	def state_next(self, state=None):
		if not state: # advance in order
			states = iter(self.state_timeouts)
			next(it.dropwhile(lambda k: k != self._state, states))
			try: self._state = next(states)
			except StopIteration: self.state_finished()
		else: self._state = state
		self.timeout_reset()

	def state_finished(self):
		if self._timeout.active(): self._timeout.cancel()
		if not self.called: self.callback(None)

	def timeout_reset(self):
		timeout = self.state_timeouts[self._state]
		if not self._timeout:
			self._timeout = reactor.callLater( timeout,
				lambda: self.errback(self.ActivityTimeout(
					self._state, self.state_timeouts[self._state] )) )
		elif not self._timeout.active(): raise self.TooLate()
		self._timeout.reset(timeout)



@defer.inlineCallbacks
def first_result(*deferreds):
	try:
		res, idx = yield defer.DeferredList(
			deferreds, fireOnOneCallback=True, fireOnOneErrback=True )
	except defer.FirstError as err: err.subFailure.raiseException()
	defer.returnValue(res)

def _dump_trunc(v, trunc_len=100):
	if isinstance(v, Mapping):
		return dict((k, _dump_trunc(v)) for k,v in v.iteritems())
	elif isinstance(v, (list, tuple)): return [_dump_trunc(v) for v in v]
	elif not isinstance(v, types.StringTypes): v = repr(v)
	if len(v) > trunc_len: v = v[:trunc_len] + '...'
	return v


class txBoxAPI(BoxAPIWrapper):
	'Box API client.'

	#: Options to twisted.web.client.HTTPConnectionPool
	request_pool_options = dict(
		persistent = True,
		maxPersistentPerHost = 10,
		cachedConnectionTimeout = 600,
		retryAutomatically = True )

	#: These are timeouts between individual read/write ops
	#: Missing keys will have default values (from HTTPTimeout.state_timeouts)
	request_io_timeouts = dict( req_headers=60,
		req_body=20, res_headers=20, res_body=20, res_end=10 )

	#: Path string or list of strings
	ca_certs_files = b'/etc/ssl/certs/ca-certificates.crt'

	#: Dump HTTP request data in debug log (might contain all sorts of auth tokens!)
	debug_requests = False


	def __init__(self, *argz, **kwz):
		super(txBoxAPI, self).__init__(*argz, **kwz)
		pool = self.request_pool = QuietHTTPConnectionPool( reactor,
				debug_requests=self.debug_requests, **self.request_pool_options )
		self.request_agent = ContentDecoderAgent(RedirectAgent(Agent(
			reactor, TLSContextFactory(self.ca_certs_files), pool=pool )), [('gzip', GzipDecoder)])


	@defer.inlineCallbacks
	def request( self, url, method='get', data=None,
			files=None, raw=False, headers=dict(), raise_for=dict() ):
		if self.debug_requests:
			url_debug = _dump_trunc(url)
			log.debug('HTTP request: {} {} (h: {}, data: {}, files: {}), raw: {}'.format(
				method, url_debug, headers, _dump_trunc(data), _dump_trunc(files), raw ))

		timeout = HTTPTimeout(**self.request_io_timeouts)

		method, body = method.lower(), None
		headers = dict() if not headers else headers.copy()
		headers.setdefault('User-Agent', 'txBox')

		if data is not None:
			if method == 'post':
				headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
				body = FileBodyProducer(io.BytesIO(urlencode(data)), timer=timeout)
			else:
				headers.setdefault('Content-Type', 'application/json')
				body = FileBodyProducer(io.BytesIO(
					urlencode(json.dumps(data)) ), timer=timeout)

		if files is not None:
			boundary = os.urandom(16).encode('hex')
			headers.setdefault( 'Content-Type',
				'multipart/form-data; boundary={}'.format(boundary) )
			body = MultipartDataSender(files, boundary, timer=timeout)
			yield body.calculate_length()

		if isinstance(url, unicode): url = url.encode('utf-8')
		if isinstance(method, unicode): method = method.encode('ascii')

		res_deferred = first_result( timeout,
			self.request_agent.request( method.upper(), url,
				Headers(dict((k,[v]) for k,v in (headers or dict()).viewitems())), body ) )
		code = res_body = None
		try:
			res = yield res_deferred
			code = res.code
			if code == http.NO_CONTENT: defer.returnValue(None)
			if code not in [http.OK, http.CREATED]:
				if self.debug_requests:
					res_body = defer.Deferred()
					res.deliverBody(DataReceiver(res_body, timer=timeout))
					res_body = yield first_result(timeout, res_body)
					log.debug('HTTP error response body: {!r}'.format(res_body))
				raise ProtocolError(code, res.phrase)

			res_body = defer.Deferred()
			res.deliverBody(DataReceiver(res_body, timer=timeout))
			res_body = yield first_result(timeout, res_body)

			if self.debug_requests:
				log.debug( 'HTTP request done ({} {}): {} {} {}, body_len: {}'\
					.format(method, url_debug, code, res.phrase, res.version, len(res_body)) )
			defer.returnValue(json.loads(res_body) if not raw else res_body)

		except ( timeout.ActivityTimeout, TimeoutError,
				ResponseFailed, RequestNotSent, RequestTransmissionFailed ) as err:
			if isinstance(err, timeout.ActivityTimeout):
				if not res_deferred.called: res_deferred.cancel()
				if res_body and not res_body.called: res_body.cancel()
			if self.debug_requests:
				log.debug(
					'HTTP transport (underlying protocol) error ({} {}): {}'\
					.format(method, url_debug, err.message or repr(err.args)) )
			raise UnderlyingProtocolError(err)

		except ProtocolError as err:
			if self.debug_requests:
				log.debug(
					'HTTP request handling error ({} {}, code: {}): {}'\
					.format(method, url_debug, code, err.message) )
			raise raise_for.get(code, ProtocolError)(code, err.message)

		except RequestGenerationFailed as err:
			err[0][0].raiseException()

		finally: timeout.state_finished()


	@defer.inlineCallbacks
	def __call__( self, url, query=dict(),
			query_filter=True, auth_header=False,
			auto_refresh_token=True, **request_kwz ):
		'''Make an arbitrary call to LiveConnect API.
			Shouldn't be used directly under most circumstances.'''
		if query_filter:
			query = dict( (k,v) for k,v in
				query.viewitems() if v is not None )
		if auth_header:
			request_kwz.setdefault('headers', dict())\
				['Authorization'] = 'Bearer {}'.format(self.auth_access_token)
		kwz = request_kwz.copy()
		kwz.setdefault('raise_for', dict())[401] = AuthenticationError
		api_url = ft.partial( self._api_url,
			url, query, pass_access_token=not auth_header )
		try: res = yield self.request(api_url(), **kwz)
		except AuthenticationError:
			if not auto_refresh_token: raise
			yield self.auth_get_token()
			if auth_header: # update auth header with a new token
				request_kwz['headers']['Authorization']\
					= 'Bearer {}'.format(self.auth_access_token)
			# Existing connections seem to hang occasionally after token updates,
			#  though it looks like a twisted issue, since they hang forever (no timeouts in place)
			self.request_pool.closeCachedConnections()
			res = yield self.request(api_url(), **request_kwz)
		defer.returnValue(res)


	@defer.inlineCallbacks
	def auth_get_token(self, check_state=True):
		'Refresh or acquire access_token.'
		res = self.auth_access_data_raw = yield self._auth_token_request()
		defer.returnValue(self._auth_token_process(res, check_state=check_state))



class txBox(txBoxAPI):
	'More biased Box interface with some convenience methods.'

	@defer.inlineCallbacks
	def resolve_path( self, path,
			root_id='0', objects=False ):
		'''Return id (or metadata) of an object, specified by chain
				(iterable or fs-style path string) of "name" attributes of it's ancestors,
				or raises DoesNotExists error.
			Requires a lot of calls to resolve each name in path, so use with care.
			root_id parameter allows to specify path
				 relative to some folder_id (default: 0).'''
		if path:
			if isinstance(path, types.StringTypes):
				path = filter(None, path.split(os.sep))
			if path:
				try:
					for i, name in enumerate(path):
						root_id = dict(it.imap(
							op.itemgetter('name', 'id'), (yield self.listdir(root_id)) ))[name]
				except (KeyError, ProtocolError) as err:
					if isinstance(err, ProtocolError) and err.code != 404: raise
					raise DoesNotExists(root_id, path[i:])
		defer.returnValue(root_id if not objects else (yield self.info(root_id)))

	@defer.inlineCallbacks
	def listdir(self, folder_id='0', type_filter=None, offset=None, limit=None):
		'''Return a list of objects in the specified folder_id.
			limit is passed to the API, so might be used as optimization.
			type_filter can be set to type (str) or sequence
				of object types to return, post-api-call processing.'''
		res = yield super(txBox, self).listdir(folder_id=folder_id, limit=limit)
		if res['total_count'] > 1000: # api limit on returned items
			# Can be worked around by splitting request into multiple ones here
			raise APILimitationError( 'API enumeration-op response contains'
				' too many items ({}) - can be truncated.'.format(res['total_count']) )
		lst = res['entries']
		if type_filter:
			if isinstance(type_filter, types.StringTypes): type_filter = {type_filter}
			lst = list(obj for obj in lst if obj['type'] in type_filter)
		defer.returnValue(lst)

	@defer.inlineCallbacks
	def get_quota(self):
		'Return tuple of (bytes_available, bytes_quota).'
		du, ds = op.itemgetter('space_used', 'space_amount')\
			((yield super(txBox, self).get_user_info()))
		defer.returnValue((ds - du, du))



class txBoxPluggableSync(txBox):

	config_update_keys = ['auth_access_token', 'auth_refresh_token']

	#: Should be set on init or overidden in subclass
	config_update_callback = None

	def __init__(self, *argz, **kwz):
		super(txBoxPluggableSync, self).__init__(*argz, **kwz)
		if not self.config_update_callback:
			raise TypeError('config_update_callback must be set')

	def sync(self):
		if not self.config_update_callback:
			raise TypeError('config_update_callback must be set')
		self.config_update_callback(**dict(
			(k, getattr(self, k)) for k in self.config_update_keys ))

	@ft.wraps(txBox.auth_get_token)
	def auth_get_token(self, *argz, **kwz):
		d = defer.maybeDeferred(super(
			txBoxPluggableSync, self ).auth_get_token, *argz, **kwz)
		d.addCallback(lambda ret: [self.sync(), ret][1])
		return d

	def __del__(self): self.sync()




if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	twisted_log.PythonLoggingObserver().start()


	_no_fallback = object()
	def read_conf(name, fallback=_no_fallback):
		try:
			with open('box_{}'.format(name)) as src:
				return src.read().strip()
		except (OSError, IOError):
			if fallback is _no_fallback: raise
			return fallback

	def write_conf(name, val):
		with open('box_{}'.format(name), 'w') as dst: dst.write(val)

	try: client_id, client_secret = map(read_conf, ['client_id', 'client_secret'])
	except (OSError, IOError):
		raise KeyError('Create "box_client_id" and "box_client_secret" files.')

	try: auth_code = read_conf('auth_code')
	except (OSError, IOError):
		api = txBox(client_id=client_id, client_secret=client_secret)
		log.info(
			'\n\n'
			'Visit the following URL in any web browser (firefox, chrome, safari, etc),\n'
				'  authorize there, confirm access permissions, and paste URL of an empty page\n'
				'  (starting with "https://success.box.com/") you will get\n'
				'  redirected to in the end into "box_auth_code" file.\n\n'
			' URL to visit: {}\n'.format(api.auth_user_get_url()) )
		raise KeyError('Need "box_auth_code" file.')

	if re.search(r'^https?://', auth_code):
		api = txBox(client_id=client_id, client_secret=client_secret)
		api.auth_user_process_url(auth_code)
		auth_code = api.auth_code
		write_conf('auth_code', auth_code)

	access_token = read_conf('access_token', None)
	refresh_token = read_conf('refresh_token', None)

	def token_update_handler(auth_access_token, auth_refresh_token, **kwargs):
		if auth_access_token is not None:
			write_conf('access_token', auth_access_token)
		if auth_refresh_token is not None:
			write_conf('refresh_token', auth_refresh_token)
		if kwargs:
			log.msg( 'Received unhandled Box access'
				' data, discarded: {}'.format(', '.join(kwargs.keys())) )


	@defer.inlineCallbacks
	def test():
		req_pool_optz = txBoxPluggableSync.request_pool_options.copy()

		api = txBoxPluggableSync(
			client_id=client_id, client_secret=client_secret, auth_code=auth_code,
			auth_access_token=access_token, auth_refresh_token=refresh_token,
			config_update_callback=token_update_handler,
			debug_requests=True, request_pool_options=req_pool_optz )

		log.info('Quota: df={}, ds={}'.format(*(yield api.get_quota())))
		log.info('Root listdir: {}'.format(map(op.itemgetter('name'), (yield api.listdir()))))

		# try: file_id = yield api.resolve_path('README.md')
		# except DoesNotExists: log.info('File not found')
		# else: api.delete(file_id)

		# from twisted.web._newclient import RequestGenerationFailed, ResponseFailed
		# try: res = yield api.put('README.md')
		# except (RequestGenerationFailed, ResponseFailed) as err:
		# 	err[0][0].raiseException()
		# log.info('Uploaded: {}'.format(res))

	def done(res):
		if reactor.running: reactor.stop()
		return res

	reactor.callWhenRunning(
		lambda: defer.maybeDeferred(test).addBoth(done) )
	reactor.run()

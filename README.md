txboxdotnet
----------------------------------------

Twisted-based python async interface for [Box (box.net) API (version
2.0)](http://developers.box.com/).

 * API docs: http://developers.box.com/docs/
 * API Auth docs: http://developers.box.com/oauth/


Usage Example
----------------------------------------

Following script will print listing of the root box.net folder, upload
"test.txt" file there, try to find it in updated folder listing and then remove
it.

	from twisted.internet import defer, reactor
	from txboxdotnet import txBoxAPI

	config = dict(client_id=..., client_secret=..., ...)

	@defer.inlineCallbacks
	def do_stuff():
		api = txBoxAPI(**config)

		# Print root directory listing
		print (e['name'] for e in (yield api.listdir()))

		# Upload "test.txt" file from local current directory
		file_info = yield api.put('test.txt')

		# Find just-uploaded "test.txt" file by name
		file_id = yield api.resolve_path('test.txt')

		# Check that id matches uploaded file
		assert file_info['id'] == file_id

		# Remove the file
		yield api.delete(file_id)

	do_stuff().addBoth(lambda ignored: reactor.stop())
	reactor.run()

Note that "config" dict above should contain various authentication data, which
for the most part, can be derived from "client_id" and "client_secret", provided
after app registration [on box.net](http://www.box.net/developers/services).

For more complete example (including oauth2 stuff), see
[api_v2.py](https://github.com/mk-fg/txboxdotnet/blob/master/txboxdotnet/api_v2.py)
code after `if __name__ == '__main__':` (will need better examples in the
future, patches welcome!).


Installation
----------------------------------------

It's a regular package for Python 2.7 (not 3.X).

Using [pip](http://pip-installer.org/) is the best way:

	% pip install txboxdotnet

If you don't have it, use:

	% easy_install pip
	% pip install txboxdotnet

Alternatively ([see
also](http://www.pip-installer.org/en/latest/installing.html)):

	% curl https://raw.github.com/pypa/pip/master/contrib/get-pip.py | python
	% pip install txboxdotnet

Or, if you absolutely must:

	% easy_install txboxdotnet

But, you really shouldn't do that.

Current-git version can be installed like this:

	% pip install 'git+https://github.com/mk-fg/txboxdotnet.git#egg=txboxdotnet'

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use "install --user",
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.


### Requirements

* [Python 2.7 (not 3.X)](http://python.org)

* [Twisted](http://twistedmatrix.com) (core, web, at least 12.2.0)


Implemented methods
----------------------------------------

Matrix of implemented API method wrappers (same order as in the
[docs](http://developers.box.com/docs/)):

- folders

	- [x] list: `listdir`
	- [x] create: `mkdir`
	- [x] get info: `info_folder`
	- [ ] copy
	- [x] delete: `delete_folder`
	- [ ] update info
	- [ ] create shared link
	- [ ] view discussions
	- [ ] view collaborations
	- [ ] list from trash
	- [ ] info from trash
	- [ ] restore from trash
	- [ ] delete permanently

- files

	- [x] upload: `put`
	- [x] download: `get`
	- [x] get info: `info_file`
	- [x] upload overwrite: `put`
	- [ ] upload rename
	- [ ] view versions
	- [ ] update info
	- [x] delete: `delete_file`
	- [ ] copy
	- [ ] create shared link
	- [ ] view comments
	- [ ] get thumbnail
	- [ ] get from trash
	- [ ] restore from trash
	- [ ] delete permanently

- comments
- discussions
- collaborations

- users

	- [x] current user info: `info_user`
	- [ ] all the rest ;)

- search
- shared items
- events

Note that these wrappers tend to be very thin, just taking python method
arguments and translating these into appropriate API keys, typically looking
somewhat like this:

	def info_file(self, file_id):
	  return self(join('files', file_id))

Any missing methods can also be replaced by calling api object in the same way
as above, passing all the appropriate (as per docs) parameters.

My purposes are quite narrow - I use service only for file storage - so missing
sharing/collaboration wrappers are unlikely to be implemented here without
patches from someone interested in having these.

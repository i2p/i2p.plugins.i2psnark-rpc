This is a Transmission- and Vuze- compatible RPC server for i2psnark,
with the Vuze-modified Transmission web UI.

To access the web UI, go to /transmission/web/ in your router console.

To use any compatible RPC client software, such as transmission-remote,
specify port 7657. For example, to list the torrents:

transmission-remote 7657 -l

Most basic features are supported. Several advanced features are not supported.
Some may be added in a future release.
Please report bugs on git.idk.i2p.

NOTE: The transmission.war binary in this plugin may also be used to add
RPC features to i2psnark-standalone.
See http://zzz.i2p/topics/3688 or the readme.txt in your i2psnark-standalone
installation for instructions.

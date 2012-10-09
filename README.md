ossfs
=======

Ossfs is a userspace filesystem to mount the Open Storage Service from Aliyun as a local filesystem. It is implemented using FUSE.

dependency
==========

fuse >= 2.8.4
libcurl >= 4
glib-2.0 >= 2.24
libxml-2.0 >= 2.7.8

install
=======

1. Get source code using git.
On Linux: open a terminal, change to the directory you want to place the source code, run the following command

	git clone https://github.com/samsong8610/ossfs.git

you will get all the source code files into ossfs subdirectory.

2. Build it.
On Linux: using the following command

	cd ossfs
	./configure
	make
	sudo make install

how to use
==========

1. First you need register an aliyun account from https://member.aliyun.com/.
2. Login using your account, and go to http://i.aliyun.com/access_key/ to create an access id/key pair.
3. Create a bucket, for example mybucket, from http://i.aliyun.com/dashboard/instance?type=oss .
4. Copy default config file to ~/.config/ossfs/ .

	mkdir -p ~/.config/ossfs/
	cp conf ~/.config/ossfs/

5. Open ~/.config/ossfs/conf using your favorate editor, and modify the following config.

	host: if you use a vm server from aliyun, you should set host to the intranet url.
	accessid: set to your access id created in step 2.
	accesskey: set to your access key created in step 2.

6. Make your mount directory, for example /mnt/oss.
7. Mount your bucket to /mnt/oss using following command

	ossfs -b mybucket /mnt/oss

8. Now, you can access your object from /mnt/oss.
9. Use command below to umount ossfs. You must leave out the /mnt/oss before umount.

	fusermount -u /mnt/oss

10. Have fun.

report bugs
===========

Ossfs v0.1 is very basic, even not support multipart upload API, and testing is not enough, so if you need this tool, please send bugs you found to https://github.com/samsong8610/ossfs/issues. Or send me a mail to samsong8610@gmail.com.

Any suggestions or new feature requests are also welcomed, send me a mail to samsong8610@gmail.com.

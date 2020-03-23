
libs: libs/libappcrypaes.a

libs/libappcrypaes.a:
	$(MAKE) -C appcryp-aes libappcrypaes.a
	mkdir -p libs
	cp -f appcryp-aes/libappcrypaes.a libs/

clean:
	rm -rf libs/* appcryp-aes
	

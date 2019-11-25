all:
	make  demo	

demo:main.c
	gcc  -Wall  -o   $@  main.c vcert.c vchain.c -I include -L ./lib -lcrypto -lssl
clean:
	rm   demo





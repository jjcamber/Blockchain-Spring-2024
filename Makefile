all: bchoc

bchoc: blockchain.py
	cp blockchain.py bchoc
	echo '#!/usr/bin/env python3' > temp
	cat bchoc >> temp
	mv temp bchoc
	chmod +x bchoc
	dos2unix bchoc

clean:
	rm -f bchoc blockchain.bin

.PHONY: all clean
import json
import sys

size = json.load(open("packet_size.txt"))
size['size'] = int(sys.argv[1])
json.dump(size, open("packet_size.txt",'w'))

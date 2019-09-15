import json
import sys

prices = json.load(open("peer_prices.txt"))
prices['mfwnjj1Jbd1uwXbj5Q4FUjmkEcGqQQsYDn'] = int(sys.argv[1])
json.dump(prices, open("peer_prices.txt",'w'))
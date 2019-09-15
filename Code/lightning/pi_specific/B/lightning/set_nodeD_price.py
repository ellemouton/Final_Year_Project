import json
import sys

prices = json.load(open("peer_prices.txt"))
prices['mmqrZXdvAi8mcjvXGJX2eJdA37kWXmCWjW'] = int(sys.argv[1])
json.dump(prices, open("peer_prices.txt",'w'))

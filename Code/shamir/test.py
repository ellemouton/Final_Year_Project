import shamir


num_packets = int(input("N? "))

secret, shares = shamir.make_random_shares(num_packets,num_packets)

#print(secret)
#print(shares)

print(shamir.recover_secret(shares))

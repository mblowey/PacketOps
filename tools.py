"""
Author: Mitchell Blowey

Miscellaneous tools and helper functions.
"""

# Used to simulate 16 bit ones-complement addition, which does not exist in python.
def _carry_around_add(a, b):
	# Start by simply adding together the numbers.
    c = a + b

    # The overflow bits are collected by the expression c >> 16 and added back to the 
    # rest of the number, which is obtained by c & 0xffff.
    return (c >> 16) + (c & 0xffff)

# Calculates the ipv4 header checksum using the passed in header, which should be
# the header completely filled in, in byte format.
def chksum(header):
	# Convert the byte format to int
	header = int.from_bytes(header, 'big', signed=False)

	words = []

	# Breaks the header into 8 bit words and adds them to the array.
	while header > 0:
		next_word = header & 0xff
		header = header >> 8

		words.append(next_word)

	# Appends an extra 0 to create an even amount of 8 bit words.
	if len(words) % 2 == 1:
		words.append(0)

	# Calculate the 16 bit ones complement sum
	sum_ = 0
	for i in range(0, len(words), 2):
		word_16_bit = (words[i+1] << 8) + words[i] # Convert two 8 bit words into 16 bit word.
		sum_ = _carry_around_add(sum_, word_16_bit) # Add new 16 bit word to current sum.

	# Return the 16 bit one's complement of the 16 bit one's complement sum.
	return ~sum_ & 0xffff

# Function to print values from a dictionary, such as the dict of attributes from an object.
# Starts_with can be specified if you only want to view the data from one levl ofthe stack, 
# e.g. starts_with='ip_' to only view fields that belong to the IP header.
def print_key_val(dictionary, starts_with=''):

    for i in sorted(dictionary.keys()):
    	if i[:len(starts_with)] == starts_with:
    		# Format the results into columns, including a decimal and hex column.
    		print('{0:<15} {1:>15} {2:>15}'.format(i, 
    											   str(dictionary[i]), 
    											   str(hex(dictionary[i]))
    											   ))
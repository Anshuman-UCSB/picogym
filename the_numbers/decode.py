nums = [16,9,3,15,3,20,6,20,8,5,14,21,13,2,5,18,19,13,1,19,15,14]
print("".join(map(lambda x: chr(x -1+ ord('a')), nums)))
'''
To extract the ranges of tls segments of the essential 
POST requests from all the pcaps for a particular activity
'''
import pyshark 
import os

def main():

	# to get hold of all the files from a directory at once
    path=input("Enter the path name to retweet directory : ")
    l=os.listdir(path)
    # to keep a track of all the unique tls segments extracted from all the files ---- rename as login,follow,favourite as per the activity
    retweet=set()

    #traversing through all the files obtained 

    for i in l:

        f=open(path+"/"+str(i),'r')

        # We filter only the application packets because that is what we are interested in examining 
		cap=pyshark.FileCapture(f,only_summaries=False,display_filter='tls.record.content_type==23')
        
        for pkt in cap:
            try:
            	idx=pkt.http2.stream.find('POST')
            	'''
            	 ----NOTE----

            	 Use the following POST requests for the corresponding activities 
            	 * Login --- 'POST /v1/profile'
            	 * Follow --- 'POST /1.1/friendships/create.json'
            	 * Favourite --- 'POST /1.1/favorites/create.json'
            	 * Retweet --- 'POST /1.1/statuses/retweet.json'

            	 '''

            	if pkt.http2.stream[idx:]=='POST /1.1/statuses/retweet.json':
            		retweet.add(pkt.tls.record_length)
            except:
            	continue

        f.close()
    #print(list(retweet))

    #appending all our findings in a common file that will contain unique data sizes from all kinds of activities

    with open('ranges.txt','a') as f:
    	f.write('\n')
    	for val in retweet:
    		f.write(str(val))
    		f.write('\n')

if __name__ == "__main__":
    #read()
    main()
    #dmain()
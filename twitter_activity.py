'''
* USE THE RANGES FILE TO EXTRACT THE MAXIMUM AND MINIMUM LIMIT OF TLS SEGMENT OF EACH ACTIVITY
* PREDICT WHAT ACTIVITIES ARE GOING ON THAT CAPTURED PCAP FILE

CUSTOM INPUT : Enter path to the file to predict : *enter the location to the file whose activity you want to predict in your local machine*
'''

import pyshark


#for checking the validity of the assumed retweet/favorite/follow behaviour
def find_activity(next_seq_num,cap):
	for pkt in cap:
		try:
			# we use tcp segment indexing because we want to examine only the immediately next packet
			if int(pkt.tcp.seq)==next_seq_num:
				if int(pkt.tls.record_length)==75:
					return 'retweet and favourite'
				if int(pkt.tls.record_length)>=240 and int(pkt.tls.record_length)<=260:
					return 'follow'
		except:
			continue
	return 'unpredictable'

#for checking the validity of the assumed login behaviour
def find_activity1(next_seq_num,cap):
	for pkt in cap:
		try:
			if int(pkt.tcp.seq)==next_seq_num:
				if int(pkt.tls.record_length)>=255 and int(pkt.tls.record_length)<=265:
					return 'login'
		except:
			continue
	return 'unpredictable'


def main():

	#opening the file created by the range.py to extract the ranges

	with open('ranges.txt','r') as f:
		for count,line in enumerate(f,0):
			if count==1:
				login=line.split(",")
				login.pop()
				login1=[int(i) for i in login]
				maxl,minl=max(login1),min(login1)
			if count==2:
				follow=line.split(",")
				follow.pop()
				follow1=[int(i) for i in follow]
				maxf,minf=max(follow1),min(follow1)
			if count==3:
				favourite=line.split(",")
				favourite.pop()
				favourite1=[int(i) for i in favourite]
				maxfv,minfv=max(favourite1),min(favourite1)
			if count==4:
				retweet=line.split(",")
				retweet.pop()
				retweet1=[int(i) for i in retweet]
				maxr,minr=max(retweet1),min(retweet1)

	path=input("Enter path to the file to predict : ")
	cap=pyshark.FileCapture(path,only_summaries=False,display_filter='tls.record.content_type==23')

	result='unpredictable'				#initialising the result value
	maxcomp=max(maxf,maxfv,maxr)		#finding the largest limit
	mincomp=min(minf,minfv,minr)		#finding the smallest limit
	activity=set()						#to store all the different activities 

	for pkt in cap:
		try:
			if int(pkt.tls.record_length)>=mincomp and int(pkt.tls.record_length)<=maxcomp:
				#calculating the next sequence number for that packet to perform the analysis on the immediately next packet
				next_seq_num=int(pkt.tcp.len)+int(pkt.tcp.seq)
				result=find_activity(next_seq_num,cap)
				#adding to the set of activities for extracting all actions carried out
				activity.add(result)
			elif int(pkt.tls.record_length)>=minl and int(pkt.tls.record_length)<=maxl:	
				#calculating the next sequence number for that packet to perform the analysis on the immediately next packet	
				next_seq_num=int(pkt.tcp.len)+int(pkt.tcp.seq)
				result=find_activity1(next_seq_num,cap)
				#adding to the set of activities for extracting all actions carried out
				activity.add(result)
		except:
			continue

	#displaying the different activities undertaken in a particular pcap
	activity=list(activity)
	idx=path.rfind('/')
	print("The activities carried out in "+path[idx+1:]+" are")
	for act in activity:
		if act!='unpredictable':
			if act=='retweet and favourite':
				print('retweet')
				print('favourite')
			else:
				print(act)

if __name__ == "__main__":
    #read()
    main()
    #dmain()



'''
USING THE TLS SEGMENTS IN PREVIOUS CODE TO NOW PREDICT THE BEHAVIOUR OF OTHER PCAPS ---- 
--------- WHETHER THE ARE BOT OR MANUAL

CUSTOM INPUT : Enter the path to the file you wish to predict : *enter the location to the directory in your local machine*
'''


import pyshark

def main():

    #bot_manual_data file contains output of the previous program where we computed the different lists
    with open("bot_manual_data","r") as f:
        for count,line in enumerate(f,0):
            if count==1:
                MANUAL=line.split(",")
                MANUAL.pop()
            if count==2:
                BOT=line.split(",")
                BOT.pop()
            if count==3:
                COMMON=line.split(",")
                COMMON.pop()
    

    manual_c,bot_c,common_c,none_c=0,0,0,0

    path=input("Enter the path to the file you wish to predict : ")
    cap=pyshark.FileCapture(path,only_summaries=False,display_filter='tls.record.content_type==23')

    for pkt in cap:
        try:
            if (pkt.tls.record_length) in COMMON:
                common_c+=1
            elif (pkt.tls.record_length) in MANUAL:
                manual_c+=1
            elif (pkt.tls.record_length) in BOT:
                bot_c+=1 
            else:
                none_c+=1
        except:
            continue

    #calculating the percentage of similarity between the activity in current pcap with bot/manual

    total=common_c+bot_c+manual_c+none_c

    idx=path.rfind("/")
    print(path[idx+1:]+" contains")
    print(str(round((manual_c/total)*100,2))+"% manual traffic")
    print(str(round((bot_c/total)*100,2))+"% bot traffic")
    print(str(round((common_c/total)*100,2))+"% common traffic")
    print(str(round((none_c/total)*100,2))+"% traffic that does not comply with the traffic pattern")

if __name__ == "__main__":
    #read()
    main()
    #dmain()

        

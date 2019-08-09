import pandas as pand

# load packages information from .csv file

file = pand.read_csv('in.csv',sep=',')

# make array witch contains all protocols we have

protocols = []

for x in file['Protocol']:

    if x not in protocols:

        protocols.append(str(x))

print(protocols)

filedf = pand.DataFrame(file)

# group by the protocol

tcpgroup = filedf.groupby('Protocol')

# the main loop

for y in protocols:

   tcp = tcpgroup.get_group(y)

   tcpupdate = pand.concat([tcp['Source'],tcp['Destination'],tcp['Source_port'],tcp['Dest_port']],axis=1)

   print(y + 'exchange stats')

   print(tcpupdate)

# find the port stats

   tcpupdate = pand.DataFrame(tcpupdate.groupby(['Source','Destination','Source_port','Dest_port'])['Source'].count())

   tcpupdate = tcpupdate.rename(columns = { 'Source' : 'Requests' })

# output the portstats

   print('Port stats:')

   print(tcpupdate)

   tcpupdate.to_csv(y + 'Output.csv')

# select most recent pair between them

   print('The most active pair was:')

   stats = pand.concat([tcp['Source'],tcp['Destination']],axis=1)

   stats['uniq'] = stats['Source'] + ' ---> ' + stats['Destination']

   count = stats['uniq'].value_counts() [:1]

   print(count)

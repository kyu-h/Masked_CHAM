import numpy as np

HW2 = [bin(n).count("1") for n in range(0,65536)]

def XOR(pt, keyguess):
    return pt ^ keyguess
def ROL(W, i):
    return (((W)<<(i)) | ((W)>>(16-(i))))

traces = np.load(r'/home/kyu/chipwhisper/chipwhisperer/software/0123_kyu_cham_64128_data/traces/2019.01.23-14.06.39_traces.npy')
pt = np.load(r'/home/kyu/chipwhisper/chipwhisperer/software/0123_kyu_cham_64128_data/traces/2019.01.23-14.06.39_textin.npy')

numtraces = np.shape(traces)[0] #50
numpoint = np.shape(traces)[1] #3000

s_pt = [0] * 4
X = [[0 for cols in range(4)]for rows in range(numtraces)]

for ptnum in range(0, numtraces):
    s_pt[0] = ('%02x%02x' % (pt[ptnum][0], pt[ptnum][1]))
    s_pt[1] = ('%02x%02x' % (pt[ptnum][2], pt[ptnum][3]))
    s_pt[2] = ('%02x%02x' % (pt[ptnum][4], pt[ptnum][5]))
    s_pt[3] = ('%02x%02x' % (pt[ptnum][6], pt[ptnum][7]))
    X[ptnum][0] = (int(s_pt[0], 16))
    X[ptnum][1] = (int(s_pt[1], 16))
    X[ptnum][2] = (int(s_pt[2], 16))
    X[ptnum][3] = (int(s_pt[3], 16))

bestguess = [0] * 16
tmp0 = 0
tmp1 = 0
tmp2 = 0
tmp3 = 0
tmp4 = 0
for bnum in range(0, 16):
    cpaoutput = 0 #cpaoutput = [0]*256
    maxcpa = [0]*1
    tmp = [0]*1
    key = 0

    for kguess0 in range(0, 256): #kguess == secret key
        for kguess1 in range(0, 256):
            ksum = ('%02x%02x' % (kguess0, kguess1))
            kguess = int(ksum, 16)
            #print ("Subkey %d, hyp = %04x"%(bnum, kguess))

            #Initialize arrays & variables to zero
            sumnum = np.zeros(numpoint)
            sumden1 = np.zeros(numpoint)
            sumden2 = np.zeros(numpoint)

            hyp = np.zeros(numtraces)

            for tnum in range(0, numtraces):
                if(bnum % 2 == 0):
                    tmp0 = (ROL(X[tnum][1], 1))
                    if (tmp0 > 65535): #make unsigned short type
                        tmp0 = hex(tmp0 & 0xffff)
                        tmp0 = int(tmp0, 16)
                    tmp1 = (XOR(tmp0, kguess))
                    if (tmp1 > 65535): #make unsigned short type
                        tmp1 = hex(tmp1 & 0xffff)
                        tmp1 = int(tmp1, 16)
                    tmp2 = (X[tnum][0] ^ (bnum))
                    if (tmp2 > 65535): #make unsigned short type
                        tmp2 = hex(tmp2 & 0xffff)
                        tmp2 = int(tmp2, 16)
                    tmp3 = (tmp1 + tmp2) #attack point
                    if (tmp3 > 65535): #make unsigned short type
                        tmp3 = hex(tmp3 & 0xffff)
                        tmp3 = int(tmp3, 16)
                    tmp4 = (ROL(tmp3, 8))
                    if (tmp4 > 65535):
                        tmp4 = hex(tmp4 & 0xffff)
                        tmp4 = int(tmp4, 16)
                else:
                    tmp0 = (ROL(X[tnum][1], 8))
                    if (tmp0 > 65535): #make unsigned short type
                        tmp0 = hex(tmp0 & 0xffff)
                        tmp0 = int(tmp0, 16)
                    tmp1 = (XOR(tmp0, kguess))
                    if (tmp1 > 65535): #make unsigned short type
                        tmp1 = hex(tmtmp1p0 & 0xffff)
                        tmp1 = int(tmp1, 16)
                    tmp2 = (X[tnum][0] ^ (bnum))
                    if (tmp2 > 65535): #make unsigned short type
                        tmp2 = hex(tmp2 & 0xffff)
                        tmp2 = int(tmp2, 16)
                    tmp3 = (tmp1 + tmp2) #attack point
                    if (tmp3 > 65535):
                        tmp3 = hex(tmp3 & 0xffff)
                        tmp3 = int(tmp3, 16)
                    tmp4 = (ROL(tmp3, 1))
                    if (tmp4 > 65535):
                        tmp4 = hex(tmp4 & 0xffff)
                        tmp4 = int(tmp4, 16)

                hyp[tnum] = HW2[tmp4] #got problem when over 3 --> case all values are same that makes zero

            #Mean of hypothesis
            meanh = np.mean(hyp, dtype=np.float64) #got problem when over 3
            #print(meanh)

            #Mean of all points in trace
            meant = np.mean(traces, axis=0, dtype=np.float64)

            #For each trace, do the following
            for tnum in range(0, numtraces):
                hdiff = (hyp[tnum] - meanh) #got problem
                tdiff = traces[tnum,:] - meant

                sumnum = sumnum + (hdiff*tdiff)
                sumden1 = sumden1 + (hdiff*hdiff)
                sumden2 = sumden2 + (tdiff*tdiff)

            cpaoutput = sumnum / np.sqrt(sumden1 * sumden2) #square root
            maxcpa[0] = max(abs(cpaoutput))

            #print (maxcpa[0])

            if(tmp[0] < maxcpa[0]):
                tmp[0] = maxcpa[0]
                key = kguess
                print ("Round: %d / key: %04x"  % (bnum, key))
                print (maxcpa[0])

    for tnum in range(0, numtraces):
        if(bnum % 2 == 0):
            tmp0 = (ROL(X[tnum][1], 1))
            if (tmp0 > 65535): #make unsigned short type
                tmp0 = hex(tmp0 & 0xffff)
                tmp0 = int(tmp0, 16)
            tmp1 = (XOR(tmp0, key))
            if (tmp1 > 65535): #make unsigned short type
                tmp1 = hex(tmp1 & 0xffff)
                tmp1 = int(tmp1, 16)
            tmp2 = (X[tnum][0] ^ (bnum))
            if (tmp2 > 65535): #make unsigned short type
                tmp2 = hex(tmp2 & 0xffff)
                tmp2 = int(tmp2, 16)
            tmp3 = (tmp1 + tmp2) #attack point
            if (tmp3 > 65535): #make unsigned short type
                tmp3 = hex(tmp3 & 0xffff)
                tmp3 = int(tmp3, 16)
            tmp4 = (ROL(tmp3, 8))
            if (tmp4 > 65535):
                tmp4 = hex(tmp4 & 0xffff)
                tmp4 = int(tmp4, 16)
        else:
            tmp0 = (ROL(X[tnum][1], 8))
            if (tmp0 > 65535): #make unsigned short type
                tmp0 = hex(tmp0 & 0xffff)
                tmp0 = int(tmp0, 16)
            tmp1 = (XOR(tmp0, key))
            if (tmp1 > 65535): #make unsigned short type
                tmp1 = hex(tmtmp1p0 & 0xffff)
                tmp1 = int(tmp1, 16)
            tmp2 = (X[tnum][0] ^ (bnum))
            if (tmp2 > 65535): #make unsigned short type
                tmp2 = hex(tmp2 & 0xffff)
                tmp2 = int(tmp2, 16)
            tmp3 = (tmp1 + tmp2) #attack point
            if (tmp3 > 65535):
                tmp3 = hex(tmp3 & 0xffff)
                tmp3 = int(tmp3, 16)
            tmp4 = (ROL(tmp3, 1))
            if (tmp4 > 65535):
                tmp4 = hex(tmp4 & 0xffff)
                tmp4 = int(tmp4, 16)

        X[tnum][0] = X[tnum][1]
        X[tnum][1] = X[tnum][2]
        X[tnum][2] = X[tnum][3]
        X[tnum][3] = tmp4

    #Find maximum value of key
    bestguess[bnum] = key
    print ("key: %04x" % (key))

print ("Best Round Key Guess: ")
for b in bestguess: print ("%04x " % b)

secretkey = [0] * 8
atmp = 0
btmp = 0
for lp in range(0, 8):
    for kguess0 in range(0, 256): #kguess == secret key
        for kguess1 in range(0, 256):
            ksum = ('%02x%02x' % (kguess0, kguess1))
            kguess = int(ksum, 16)

            ktmp0 = (ROL(kguess, 1))
            if (ktmp0 > 65535):
                ktmp0 = hex(ktmp0 & 0xffff)
                ktmp0 = int(ktmp0, 16)

            ktmp1 = (ROL(kguess, 8))
            if (ktmp1 > 65535):
                ktmp1 = hex(ktmp1 & 0xffff)
                ktmp1 = int(ktmp1, 16)

            ktmp2 = (ROL(kguess, 11))
            if (ktmp2 > 65535):
                ktmp2 = hex(ktmp2 & 0xffff)
                ktmp2 = int(ktmp2, 16)

            if (ktmp0 ^ ktmp1 ^ kguess == bestguess[lp]):
                atmp = kguess

            if (ktmp0 ^ ktmp2 ^ kguess == bestguess[(lp+8)^lp]):
                btmp = kguess

            if (atmp == btmp):
                secretkey[lp] = kguess
            else :
                print ("%d got problem" % lp)

print ("Best Secret Key Guess: ")
for b in secretkey: print ("%04x " % b)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef unsigned int 	u32;
typedef unsigned short 	u16;

#define ROR(W,i) (((W)>>(i)) | ((W)<<(16-(i))))
#define ROL(W,i) (((W)<<(i)) | ((W)>>(16-(i))))

#define ROR32(W,i) (((W)>>(i)) | ((W)<<(32-(i))))
#define ROL32(W,i) (((W)<<(i)) | ((W)>>(32-(i))))

#define BILLION 1000000000L

u16 secretkey64[] = {0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0b0a, 0x0d0c, 0x0f0e};
u16 plaintext64[] = {0x1100, 0x3322, 0x5544, 0x7766};
u16 roundkey64[16]= {0,};

static u32 x=123456789, y=362436069, z=521288629;

u32 xorshf96(void) {
    u32 t;

    x ^= x << 16;
    x ^= x >> 5;
    x ^= x << 1;

    t = x;
    x = y;
    y = z;
    z = t ^ x ^ y;

    return z;
}

void share(u32 x,u32 a[],int n){
    int i;
    a[0]=x;
    for(i=1; i<n; i++){
        a[i]=0;
    }
}

void refresh(u32 a[],int n){
    int i;
    for(i=0; i<n-1; i++){
        u32 tmp=xorshf96(); //rand();
        a[n-1] = a[n-1] ^ tmp;
        a[i] = a[i] ^ tmp;
    }
}

u32 xorop(u32 a[],int n){
    int i;
    u32 r=0;
    for(i=0; i<n; i++){
        r ^= a[i];
    }

    return r;
}

u32 addop(u32 a[],int n){
    int i;
    u32 r=0;

    for(i=0; i<n; i++){
        r += a[i];
    }

    return r;
}

u32 Psi(u32 x,u32 y){
    return (x ^ y) - y;
}

u32 Psi0(u32 x,u32 y,int n){
    return Psi(x, y) ^ ((~n & 1) * x);
}

void copy(u32 *x,u32 *y,int n){
    for(int i=0; i<n; i++)
        x[i] = y[i];
}

void HO_BtoA(u32 *D,u32 *x,int n){
    if (n==2){
        u32 s = xorshf96();
        u32 a1 = x[0] ^ s;
        u32 a2 = x[1] ^ s;

        u32 r = xorshf96();

        D[0] = (a1 ^ Psi(a1,r ^ a2)) ^ Psi(a1,r);
        D[1] = a2;

        #ifdef DEBUG
          assert((x[0] ^ x[1])==(D[0] + D[1]));
        #endif

        return;
    }

    u32 a[n+1];
    copy(a, x, n);
    a[n] = 0;

    refresh(a, n+1);

    u32 b[n];

    b[0] = Psi0(a[0], a[1], n);

    for(int i=1; i<n; i++)
        b[i] = Psi(a[0], a[i+1]);

    #ifdef DEBUG
    assert(xorop(x,n)==(xorop(a+1,n)+xorop(b,n)));
    #endif

    u32 c[n];
    copy(c, a+1, n);
    refresh(c, n);

    u32 d[n];
    copy(d, b, n);
    refresh(d, n);

    #ifdef DEBUG
    assert(xorop(x,n)==(xorop(c,n)+xorop(d,n)));
    #endif

    c[n-2] ^= c[n-1];
    d[n-2] ^= d[n-1];

    #ifdef DEBUG
    assert(xorop(x,n)==(xorop(c,n-1)+xorop(d,n-1)));
    #endif

    u32 A[n-1], B[n-1];
    HO_BtoA(A, c, n-1);
    HO_BtoA(B, d, n-1);

    for(int i=0; i<n-2; i++){
        D[i]=A[i]+B[i];
    }

    D[n-2] = A[n-2];
    D[n-1] = B[n-2];

    #ifdef DEBUG
    assert(xorop(x,n)==addop(D,n));
    #endif
}

void timings(){
    int nt=1000;
    int n;

    for(int t=2; t<13; t++){
        if ((t==7) || (t==9) || (t==11))
            continue;

        n=t+1;
        u32 xin=242;
        u32 x[n+1];
        share(xin,x,n);
        refresh(x,n);

        u32 D[n];

        clock_t start=clock();

        for(int i=0;i<nt;i++){
            HO_BtoA(D,x,n);
        }

        clock_t end=clock();
        float dt=((float) (end-start))/CLOCKS_PER_SEC;

        //printf(" $%d$ &",(int) (dt*1000000));
        //printf("order=%d t=%f\n",t,dt);
    }
    //printf("\n");
}

u32 SecAnd(u32 x_prime, u32 y_prime, u32 s, u32 t, u32 u){
    //Do it before enter this function
    //x_prime = x ^ s;
    //y_prime = y ^ t;

    u32 z_prime = u ^ (x_prime & y_prime);
    z_prime = z_prime ^ (x_prime & t);
    z_prime = z_prime ^ (s & y_prime);
    z_prime = z_prime ^ (s & t);

    return z_prime;
}

u32 SecXor(u32 x_prime, u32 y_prime, u32 u){
    //Do it before enter this function
    //x_prime = x ^ s;
    //y_prime = y ^ u;

    u32 z_prime = x_prime ^ y_prime;
    z_prime = z_prime ^ u;

    return z_prime;
}

u32 SecShift(u32 x_prime, u32 s, u32 t, u32 j){
    //Do it before enter this function
    //x_prime = x ^ s;
    if(j < 0)
        return 0;

    u32 y_prime = t ^ (x_prime << j);
    y_prime = y_prime ^ (s << j);

    return y_prime;
}

u32 KS_AtoB(u32 A, u32 r, u32 n){
    u32 s, t, u = 0;
    u32 H, U = 0;
    u32 p_prime = A ^ s;
    p_prime = p_prime ^ r;

    u32 g_prime = s ^ ((A ^ t) & r);
    g_prime = g_prime ^ (t & r);

    for(int i=0; i<n-1; i++){
        H = SecShift(g_prime, s, t, pow(2, i-1));
        U = SecAnd(p_prime, H, s, t, u);
        g_prime = SecXor(g_prime, U, u);
        H = SecShift(p_prime, s, t, pow(2, i-1));
        p_prime = SecAnd(p_prime, H, s, t, u);
        p_prime = p_prime ^ s;
        p_prime = p_prime ^ u;
    }

    H = SecShift(g_prime, s, t, pow(2, n-1));
    U = SecAnd(p_prime, H, s, t, u);
    g_prime = SecXor(g_prime, U, u);

    u32 x_prime = A ^ 2 * g_prime;
    x_prime = x_prime ^ 2 * s;

    return x_prime;
}

void KeyGen64(u16* RK, u16*K){
	u16 tmp0, tmp1, tmp2;
	u32 i;

	for (i=0;i<8;i++){
		tmp0 = ROL(K[i],1);
		tmp1 = ROL(K[i],8);
		tmp2 = ROL(K[i],11);

		RK[i] = tmp0 ^ tmp1 ^ K[i];
		RK[((i+8)^1)] = tmp0 ^ tmp2 ^ K[i];
	}
}

void Enc64(u16* X, u16* RK){
	u16 X3, X2, X1, X0;
	X3 = X[3];
	X2 = X[2];
	X1 = X[1];
	X0 = X[0];

	u16 tmp0,tmp1,tmp2,tmp3,tmp4;
	u32 i = 0;
	u32 n=2;
	u32 nt=1000;
	u16 M[10] = {0, };

	for(int a=0;a<10;a++){
		u32 x[n+1];
		u32 D[n];

		for(int z=0; z<10; z++){
			M[z] = xorshf96();
			//printf("%04x, ", M[z]);
		}
		//printf("\n");

		//***************** 1 Round start *******************//

		//printf("%u\n", i);
		tmp0 = ROL(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		u16 tmp1_1R_L = tmp1;

		tmp1 = tmp1 ^ M[0];

		u32 xin = tmp1;
		//timings();
		share(xin,x,n);
		refresh(x,n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp1 = xorop(x,n);

		tmp2 = X0^(2*i);
		u16 tmp2_1R_L = tmp2;
		tmp2 = tmp2 ^ M[0];

		xin = tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[1] = ROL(M[1],8);
		tmp3 = tmp3 + M[1];

		tmp4 = ROL(KS_AtoB(tmp3, 0, 3),8);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		u16 tmp1_1R_R = tmp1;
		tmp1 = tmp1 ^ M[2];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		u16 tmp2_1R_R = tmp2;
		tmp2 = tmp2 ^ M[2];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[3] = ROL(M[3],1);
		tmp3 = tmp3 + M[3];

		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;

		//***************** 1 Round Finished *******************//
		//***************** 2 Round start *******************//
		//printf("%u\n", i);
		tmp0 = ROL(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		u16 tmp1_2R_L = tmp1;
		tmp1 = tmp1 ^ M[4];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		u16 tmp2_2R_L = tmp2;
		tmp2 = tmp2 ^ M[4];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[5] = ROL(M[5],8);
		tmp3 = tmp3 + M[5];

		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_1R_L + tmp2_1R_L; //K0'
		X1 = ROL(X1,8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		u16 tmp1_2R_R = tmp1;
		tmp1 = tmp1 ^ M[6];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		u16 tmp2_2R_R = tmp2;
		tmp2 = tmp2 ^ M[6];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[7] = ROL(M[7],1);
		tmp3 = tmp3 + M[7];

		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1 = tmp1_1R_R + tmp2_1R_R; //K1'
		X1 = ROL(X1,1);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;

		//***************** 2 Round Finished *******************//
		//***************** 3 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		u16 tmp1_3R_L = tmp1;
		tmp1 = tmp1 ^ M[8];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		u16 tmp2_3R_L = tmp2;
		tmp2 = tmp2 ^ M[8];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[9] = ROL(M[9],8);
		tmp3 = tmp3 + M[9];

		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_2R_L + tmp2_2R_L; //K2'
		X1 = ROL(X1,8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1 = tmp1_2R_R + tmp2_2R_R; //K3'
		X1 = ROL(X1,1);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;

		//***************** 3 Round Finished *******************//
		//***************** 4 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_3R_L + tmp2_3R_L; //K4'
		X1 = ROL(X1,8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}

		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}

		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;

		//***************** 4 Round Finished *******************//
	}

	X[3] = X3;
	X[2] = X2;
	X[1] = X1;
	X[0] = X0;
}

u32 secretkey128[] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c};
u32 plaintext128[] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
u32 roundkey128[8]= {0,};

void KeyGen128(u32* RK, u32*K){
	u32 tmp0, tmp1, tmp2;
	u32 i;

	for (i=0;i<4;i++){
		tmp0 = ROL32(K[i],1);
		tmp1 = ROL32(K[i],8);
		tmp2 = ROL32(K[i],11);

		RK[i] = tmp0 ^ tmp1 ^ K[i];
		RK[((i+4)^1)] = tmp0 ^ tmp2 ^ K[i];
	}
}

void Enc128(u32* X, u32* RK){
	u32 X3, X2, X1, X0;
	X3 = X[3];
	X2 = X[2];
	X1 = X[1];
	X0 = X[0];

	u32 tmp0,tmp1,tmp2,tmp3,tmp4;
	u32 i = 0;
	u32 n = 2;
	u32 nt = 1000;

	u32 M[10] = {0, };

	for(int a=0;a<10;a++){
		u32 x[n+1];
		u32 D[n];

		for(int z=0; z<10; z++){
			M[z] = xorshf96();
			//printf("%04x, ", M[z]);
		}
		//printf("\n");

		//***************** 1 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 8];
		u32 tmp1_1R_L = tmp1;

		tmp1 = tmp1 ^ M[0];

		u32 xin = tmp1;
		//timings();
		share(xin,x,n);
		refresh(x,n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp1 = xorop(x,n);

		tmp2 = X0^(2*i);
		u32 tmp2_1R_L = tmp2;
		tmp2 = tmp2 ^ M[0];

		xin = tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[1] = ROL32(M[1],8);
		tmp3 = tmp3 + M[1];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 8];
		u32 tmp1_1R_R = tmp1;
		tmp1 = tmp1 ^ M[2];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		u32 tmp2_1R_R = tmp2;
		tmp2 = tmp2 ^ M[2];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[3] = ROL32(M[3],1);
		tmp3 = tmp3 + M[3];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 1 Round Finished *******************//
		//***************** 2 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 8];
		u32 tmp1_2R_L = tmp1;
		tmp1 = tmp1 ^ M[4];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		u32 tmp2_2R_L = tmp2;
		tmp2 = tmp2 ^ M[4];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[5] = ROL32(M[5],8);
		tmp3 = tmp3 + M[5];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_1R_L + tmp2_1R_L; //K0'
		X1 = ROL32(X1,8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 8];
		u32 tmp1_2R_R = tmp1;
		tmp1 = tmp1 ^ M[6];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		u32 tmp2_2R_R = tmp2;
		tmp2 = tmp2 ^ M[6];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[7] = ROL32(M[7],1);
		tmp3 = tmp3 + M[7];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1 = tmp1_1R_R + tmp2_1R_R; //K1'
		X1 = ROL32(X1,1);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 2 Round Finished *******************//
		//***************** 3 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 8];
		u32 tmp1_3R_L = tmp1;
		tmp1 = tmp1 ^ M[8];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		u32 tmp2_3R_L = tmp2;
		tmp2 = tmp2 ^ M[8];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[9] = ROL32(M[9],8);
		tmp3 = tmp3 + M[9];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_2R_L + tmp2_2R_L; //K2'
		X1 = ROL32(X1, 8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 8];
		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1 = tmp1_2R_R + tmp2_2R_R; //K3'
		X1 = ROL32(X1,1);
		X2   = X3;
		X3   = tmp4;

		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 3 Round Finished *******************//
		//***************** 4 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 8];
		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_3R_L + tmp2_3R_L; //K4'
		X1 = ROL32(X1, 8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 8];
		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}

		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}

		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 4 Round Finished *******************//
	}

	X[3] = X3;
	X[2] = X2;
	X[1] = X1;
	X[0] = X0;
}


u32 secretkey256[] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc};
u32 plaintext256[] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
u32 roundkey256[16]= {0,};

void KeyGen256(u32* RK, u32*K){
	u32 tmp0, tmp1, tmp2;
	u32 i;

	for (i=0;i<8;i++){
		tmp0 = ROL32(K[i],1);
		tmp1 = ROL32(K[i],8);
		tmp2 = ROL32(K[i],11);

		RK[i] = tmp0 ^ tmp1 ^ K[i];
		RK[((i+8)^1)] = tmp0 ^ tmp2 ^ K[i];
	}
}

void Enc256(u32* X, u32* RK){
	u32 X3, X2, X1, X0;
	X3 = X[3];
	X2 = X[2];
	X1 = X[1];
	X0 = X[0];

	u32 tmp0,tmp1,tmp2,tmp3,tmp4;
	u32 i = 0;
	u32 n = 2;
	u32 nt = 1000;

	u32 M[10] = {0, };

	for(int a=0;a<12;a++){
		u32 x[n+1];
		u32 D[n];

		for(int z=0; z<10; z++){
			M[z] = xorshf96();
			//printf("%04x, ", M[z]);
		}
		//printf("\n");

		//***************** 1 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		u32 tmp1_1R_L = tmp1;
		tmp1 = tmp1 ^ M[0];

		u32 xin = tmp1;
		//timings();
		share(xin,x,n);
		refresh(x,n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp1 = xorop(x,n);

		tmp2 = X0^(2*i);
		u32 tmp2_1R_L = tmp2;
		tmp2 = tmp2 ^ M[0];

		xin = tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[1] = ROL32(M[1],8);
		tmp3 = tmp3 + M[1];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		u32 tmp1_1R_R = tmp1;
		tmp1 = tmp1 ^ M[2];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		u32 tmp2_1R_R = tmp2;
		tmp2 = tmp2 ^ M[2];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[3] = ROL32(M[3],1);
		tmp3 = tmp3 + M[3];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 1 Round Finished *******************//
		//***************** 2 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		u32 tmp1_2R_L = tmp1;
		tmp1 = tmp1 ^ M[4];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		u32 tmp2_2R_L = tmp2;
		tmp2 = tmp2 ^ M[4];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[5] = ROL32(M[5],8);
		tmp3 = tmp3 + M[5];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_1R_L + tmp2_1R_L; //K0'
		X1 = ROL32(X1,8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		u32 tmp1_2R_R = tmp1;
		tmp1 = tmp1 ^ M[6];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		u32 tmp2_2R_R = tmp2;
		tmp2 = tmp2 ^ M[6];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[7] = ROL32(M[7],1);
		tmp3 = tmp3 + M[7];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1 = tmp1_1R_R + tmp2_1R_R; //K1'
		X1 = ROL32(X1,1);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 2 Round Finished *******************//
		//***************** 3 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		u32 tmp1_3R_L = tmp1;
		tmp1 = tmp1 ^ M[8];

		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		u32 tmp2_3R_L = tmp2;
		tmp2 = tmp2 ^ M[8];

		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		M[9] = ROL32(M[9],8);
		tmp3 = tmp3 + M[9];

		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_2R_L + tmp2_2R_L; //K2'
		X1 = ROL32(X1, 8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1 = tmp1_2R_R + tmp2_2R_R; //K3'
		X1 = ROL32(X1,1);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 3 Round Finished *******************//
		//***************** 4 Round start *******************//
		//printf("%u\n", i);

		tmp0 = ROL32(X1,1);
		tmp1 = tmp0 ^ RK[2*i % 16];
		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i);
		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 8);

		X0   = X1;
		X1 = tmp1_3R_L + tmp2_3R_L; //K4'
		X1 = ROL32(X1, 8);
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		tmp0 = ROL32(X1,8);
		tmp1 = tmp0 ^ RK[(2*i + 1)% 16];
		xin = tmp1;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0; i<nt; i++){
			HO_BtoA(D, x, n);
		}
		tmp1 = xorop(x, n);

		tmp2 = X0^(2*i+1);
		xin=tmp2;
		//timings();
		share(xin, x, n);
		refresh(x, n);
		for(int i=0;i<nt;i++){
			HO_BtoA(D,x,n);
		}
		tmp2 = xorop(x, n);

		tmp3 = tmp1 + tmp2;
		tmp4 = ROL32(KS_AtoB(tmp3, 0, 3), 1);

		X0   = X1;
		X1   = X2;
		X2   = X3;
		X3   = tmp4;
		//printf("%04x %04x %04x %04x\n", X0, X1, X2, X3);

		i++;
		//***************** 4 Round Finished *******************//
	}

	X[3] = X3;
	X[2] = X2;
	X[1] = X1;
	X[0] = X0;
}

int main(void) {
    int i;
    clock_t start = (int)clock();

	KeyGen64(roundkey64,secretkey64);
	Enc64(plaintext64,roundkey64);

    printf("CHAM 64 x 128 ciphertext: ");
    for(i=0; i<4; i++){
        printf("0x%04x, ", plaintext64[i]);
    }
    printf("\n");

    KeyGen128(roundkey128,secretkey128);
    Enc128(plaintext128,roundkey128);

    printf("CHAM 128 x 128 ciphertext: ");
    for(i=0; i<4; i++){
        printf("0x%04x, ", plaintext128[i]);
    }
    printf("\n");

    KeyGen256(roundkey256,secretkey256);
    Enc256(plaintext256,roundkey256);

    printf("CHAM 128 x 256 ciphertext: ");
    for(i=0; i<4; i++){
        printf("0x%04x, ", plaintext256[i]);
    }
    printf("\n\n");

    printf("Elapsed Time: %04fs\n", (float)(clock() - start) / CLOCKS_PER_SEC);

	return EXIT_SUCCESS;
}

#include <stdint.h>
#include "skinny.h"

/**
 * SKINNY-128-384 block cipher encryption.
 * Under 48-byte tweakey at k, encrypt 16-byte plaintext at p and store the 16-byte output at c.
 * 
 * Rakenne:
 * 1.intial state
 * 2.SubCells 8-bit s-box
 * 3.AddConstants Layer
 * 4.ART Add Round Tweaky
 * 5.ShiftRows
 * 6.MixColumns
 * 
 */

uint8_t S8 [16][16] = {
//          y   x

0x65 ,0x4c ,0x6a ,0x42 ,0x4b ,0x63 ,0x43 ,0x6b ,0x55 ,0x75 ,0x5a ,0x7a ,0x53 ,0x73 ,0x5b ,0x7b ,
0x35 ,0x8c ,0x3a ,0x81 ,0x89 ,0x33 ,0x80 ,0x3b ,0x95 ,0x25 ,0x98 ,0x2a ,0x90 ,0x23 ,0x99 ,0x2b ,
0xe5 ,0xcc ,0xe8 ,0xc1 ,0xc9 ,0xe0 ,0xc0 ,0xe9 ,0xd5 ,0xf5 ,0xd8 ,0xf8 ,0xd0 ,0xf0 ,0xd9 ,0xf9 ,
0xa5 ,0x1c ,0xa8 ,0x12 ,0x1b ,0xa0 ,0x13 ,0xa9 ,0x05 ,0xb5 ,0x0a ,0xb8 ,0x03 ,0xb0 ,0x0b ,0xb9 ,
0x32 ,0x88 ,0x3c ,0x85 ,0x8d ,0x34 ,0x84 ,0x3d ,0x91 ,0x22 ,0x9c ,0x2c ,0x94 ,0x24 ,0x9d ,0x2d ,
0x62 ,0x4a ,0x6c ,0x45 ,0x4d ,0x64 ,0x44 ,0x6d ,0x52 ,0x72 ,0x5c ,0x7c ,0x54 ,0x74 ,0x5d ,0x7d ,
0xa1 ,0x1a ,0xac ,0x15 ,0x1d ,0xa4 ,0x14 ,0xad ,0x02 ,0xb1 ,0x0c ,0xbc ,0x04 ,0xb4 ,0x0d ,0xbd ,
0xe1 ,0xc8 ,0xec ,0xc5 ,0xcd ,0xe4 ,0xc4 ,0xed ,0xd1 ,0xf1 ,0xdc ,0xfc ,0xd4 ,0xf4 ,0xdd ,0xfd ,
0x36 ,0x8e ,0x38 ,0x82 ,0x8b ,0x30 ,0x83 ,0x39 ,0x96 ,0x26 ,0x9a ,0x28 ,0x93 ,0x20 ,0x9b ,0x29 ,
0x66 ,0x4e ,0x68 ,0x41 ,0x49 ,0x60 ,0x40 ,0x69 ,0x56 ,0x76 ,0x58 ,0x78 ,0x50 ,0x70 ,0x59 ,0x79 ,
0xa6 ,0x1e ,0xaa ,0x11 ,0x19 ,0xa3 ,0x10 ,0xab ,0x06 ,0xb6 ,0x08 ,0xba ,0x00 ,0xb3 ,0x09 ,0xbb ,
0xe6 ,0xce ,0xea ,0xc2 ,0xcb ,0xe3 ,0xc3 ,0xeb ,0xd6 ,0xf6 ,0xda ,0xfa ,0xd3 ,0xf3 ,0xdb ,0xfb ,
0x31 ,0x8a ,0x3e ,0x86 ,0x8f ,0x37 ,0x87 ,0x3f ,0x92 ,0x21 ,0x9e ,0x2e ,0x97 ,0x27 ,0x9f ,0x2f ,
0x61 ,0x48 ,0x6e ,0x46 ,0x4f ,0x67 ,0x47 ,0x6f ,0x51 ,0x71 ,0x5e ,0x7e ,0x57 ,0x77 ,0x5f ,0x7f ,
0xa2 ,0x18 ,0xae ,0x16 ,0x1f ,0xa7 ,0x17 ,0xaf ,0x01 ,0xb2 ,0x0e ,0xbe ,0x07 ,0xb7 ,0x0f ,0xbf ,
0xe2 ,0xca ,0xee ,0xc6 ,0xcf ,0xe7 ,0xc7 ,0xef ,0xd2 ,0xf2 ,0xde ,0xfe ,0xd7 ,0xf7 ,0xdf ,0xff
};

uint8_t round_constants [62] = {0x01,0x03,0x07,0x0f,0x1f,0x3e,0x3d,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,0x27,0x0e,
                                0x1d,0x3a,0x35,0x2B,0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,0x1C,0x38,
                                0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A,0x34,0x29,0x12,0x24,0x08,0x11,0x22,0x04,
                                0x09,0x13,0x26,0x0C,0x19,0x32,0x25,0x0A,15,0x2A,0x14,0x28,0x10,0x20};

unsigned char get_sbox(unsigned char p ){
    uint8_t y_cord = (p &0xF0)>>4;
    uint8_t x_cord = (p&0x0f);
    uint8_t out = S8[y_cord][x_cord];
    return out;
}

unsigned char bit_permutation(unsigned char p)
{
    unsigned char new_p = p;
    for(int r = 0;r<4;r++){
        unsigned char seventh   = (new_p & 0b10000000)>>7; // x0000000
        unsigned char sixth     = (new_p & 0b01000000)>>6; // 0x000000
        unsigned char fifth     = (new_p & 0b00100000)>>5; // 00x00000 
        unsigned char fourth    = (new_p & 0b00010000)>>4; // 000x0000
        unsigned char third     = (new_p & 0b00001000)>>3; // 0000x000
        unsigned char second    = (new_p & 0b00000100)>>2; // 00000x00
        unsigned char first     = (new_p & 0b00000010)>>1; // 000000x0
        unsigned char zero      = (new_p & 0b00000001)>>0; // 0000000x
        
        
        unsigned char temp = ~(seventh|sixth)&0b00000001; 
        unsigned char im4 = fourth^(temp);
        unsigned char temp2 = ~(third|second)&0b00000001; 
        unsigned char im0 = zero^(temp2);

        if(r == 3){
            new_p = (seventh<<7)|(sixth<<6)|(fifth<<5)|(fourth<<4)|(third<<3)|(first<<2)|(second<<1)|(zero);
        }
        else{
            new_p = (second<<7)|(first<<6)|(seventh<<5)|(sixth<<4)|(im4<<3)|(im0<<2)|(third<<1)|(fifth);
        }
    }
    return new_p;


}

void add_constant(unsigned char plain[],uint8_t round){
        
        unsigned char new[16];
        uint8_t rc = round_constants[round];
        unsigned char fifth     = (rc & 0b00100000)>>5; // 00x00000 
        unsigned char fourth    = (rc & 0b00010000)>>4; // 000x0000
        unsigned char third     = (rc & 0b00001000)>>3; // 0000x000
        unsigned char second    = (rc & 0b00000100)>>2; // 00000x00
        unsigned char first     = (rc & 0b00000010)>>1; // 000000x0
        unsigned char zero      = (rc & 0b00000001)>>0; // 0000000x
        uint8_t c0 = (0b00000000|(third<<3)|(second<<2)|(first<<1)|zero);
        uint8_t c1 = (0b00000000|(fifth<<1)|(fourth));
        uint8_t c2 = 0x2;
        plain[0] = plain[0]^c0;
        plain[4] = plain[4]^c1;
        plain[8] = plain[8]^c2;


    }


void add_round_tweakey(unsigned char key[], unsigned char plain[])
{   
   for(int r=0;r<=1;r++){
       for(int c=0;c<=3;c++){
           uint8_t plain_ = plain[c+r*4];
           uint8_t TK1 = key[c+4*r];
           uint8_t TK2 = key[c+4*r+16];
           uint8_t TK3 = key[c+4*r+32];
           uint8_t ans = plain_^TK1^TK2^TK3;
           plain[c+r*4] = plain[c+r*4]^key[c+4*r]^key[c+4*r+16]^key[c+4*r+32];
       }
   }
}

void tweakey_schedule(unsigned char temp[]){
    unsigned char new[48] = 
       {temp[9],   temp[15],   temp[8],   temp[13],   temp[10],   temp[14],   temp[12],   temp[11],   temp[0],   temp[1],   temp[2],   temp[3],   temp[4],   temp[5],   temp[6],   temp[7],
        temp[16+9],temp[16+15],temp[16+8],temp[16+13],temp[16+10],temp[16+14],temp[16+12],temp[16+11],temp[16+0],temp[16+1],temp[16+2],temp[16+3],temp[16+4],temp[16+5],temp[16+6],temp[16+7],
        temp[32+9],temp[32+15],temp[32+8],temp[32+13],temp[32+10],temp[32+14],temp[32+12],temp[32+11],temp[32+0],temp[32+1],temp[32+2],temp[32+3],temp[32+4],temp[32+5],temp[32+6],temp[32+7]};

        for(int i = 0;i<8;i++){
        unsigned char p = new[16+i];
        unsigned char new_p;
        unsigned char seventh   = (p & 0b10000000)>>7; // x0000000
        unsigned char sixth     = (p & 0b01000000)>>6; // 0x000000
        unsigned char fifth     = (p & 0b00100000)>>5; // 00x00000 
        unsigned char fourth    = (p & 0b00010000)>>4; // 000x0000
        unsigned char third     = (p & 0b00001000)>>3; // 0000x000
        unsigned char second    = (p & 0b00000100)>>2; // 00000x00
        unsigned char first     = (p & 0b00000010)>>1; // 000000x0
        unsigned char zero      = (p & 0b00000001)>>0; // 0000000x
        unsigned char tmp       = seventh^fifth;
        new_p = ((sixth<<7)|(fifth<<6)|(fourth<<5)|(third<<4)|(second<<3)|(first<<2)|(zero<<1)|(tmp));
        new[16+i] = new_p;       
    }
    for(int i = 0;i<8;i++){
        unsigned char p = new[16*2+i];
        unsigned char new_p;
        unsigned char seventh   = (p & 0b10000000)>>7; // x0000000
        unsigned char sixth     = (p & 0b01000000)>>6; // 0x000000
        unsigned char fifth     = (p & 0b00100000)>>5; // 00x00000 
        unsigned char fourth    = (p & 0b00010000)>>4; // 000x0000
        unsigned char third     = (p & 0b00001000)>>3; // 0000x000
        unsigned char second    = (p & 0b00000100)>>2; // 00000x00
        unsigned char first     = (p & 0b00000010)>>1; // 000000x0
        unsigned char zero      = (p & 0b00000001)>>0; // 0000000x
        unsigned char tmp       = zero^sixth;
        new_p = (((tmp)<<7)|(seventh<<6)|(sixth<<5)|(fifth<<4)|(fourth<<3)|(third<<2)|(second<<1)|(first));
        new[16*2+i] = new_p;
    }
    memcpy(temp,new,48); 


}

void shift_rows(unsigned char temp[])
{
    unsigned char new[16] = {temp[0],   temp[1],   temp[2],   temp[3],
                             temp[7],   temp[4],   temp[5],   temp[6],
                             temp[10],  temp[11],  temp[8],   temp[9],
                             temp[13],  temp[14],  temp[15],  temp[12]};

        memcpy(temp,new,16);
}

void mix_columns(unsigned char temp[])
{
    unsigned char new[16];
    for(int i = 0;i<4;i++){
        new[0 + i] = temp[i]^temp[8+i]^temp[12+i];
        new[4 + i] = temp[i]; 
        new[8 + i] = temp[4+i]^temp[8+i];
        new[12 + i] = temp[i]^temp[8+i];

    }
    memcpy(temp,new,16);

}

void sub_cells(unsigned char temp[])
{   
    
    unsigned char new[16];
    for(int i=0;i<16;i++){
        new[i] = get_sbox(temp[i]);
    }
    memcpy(temp,new,16);
    
}

void skinny(unsigned char *c, const unsigned char *p, const unsigned char *k) {
    //Copy plaintext to char array
    unsigned char plain[16] ;
    memmove(plain,p,16);
    //Copy tweakkey to array
     unsigned char key[48] ;
    memmove(key,k,48);

    for(int round = 0;round<56;round++)
    {
    sub_cells(plain);//ok
    add_constant(plain,round);//ok
    add_round_tweakey(key,plain);//ok
    tweakey_schedule(key);
    shift_rows(plain);
    mix_columns(plain);
    }
    
    memcpy(c,plain,16);
    

}


A
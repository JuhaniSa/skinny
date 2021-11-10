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
void skinny(unsigned char *c, const unsigned char *p, const unsigned char *k) {


    static const unsigned char internal_state[4][4];
    internal_state[1][1]

}



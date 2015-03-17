/**********************************************************************************
Copyright Institut Telecom
Contributors: Renaud Pacalet (renaud.pacalet@telecom-paristech.fr)

This software is a computer program whose purpose is to experiment timing and
power attacks against crypto-processors.

This software is governed by the CeCILL license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms. For more
information see the LICENCE-fr.txt or LICENSE-en.txt files.
**********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <utils.h>
#include <des.h>
#include <km.h>
#include <pcc.h>

uint64_t pt;    /* Plain text. */
uint64_t *ct;   /* Array of cipher texts. */
double *t;      /* Array of timing measurements. */

/* Allocate arrays <ct> and <t> to store <n> cipher texts and timing
 * measurements. Open datafile <name> and store its content in global variables
 * <pt>, <ct> and <t>. */
void read_datafile (char *name, int n);

/* Brute-force attack with a plain text - cipher text pair (<pt>, <ct>) and
 * partial knowledge of secret key (<km>). Print the found secret key (16 hex
 * digits) and return 1 if success, else return 0 and print nothing. */
int brute_force (des_key_manager km, uint64_t pt, uint64_t ct);

int
main (int argc, char **argv)
{
  int n;              /* Required number of experiments. */
  uint64_t r16l16;    /* Output of last round, before final permutation. */
  uint64_t l16;       /* Right half of r16l16. */
  uint64_t sbo;       /* Output of SBoxes during last round. */
  double sum;         /* Sum of timing measurements. */
  int i;              /* Loop index. */
  des_key_manager km; /* Key manager. */

  /************************************************************************/
  /* Before doing anything else, check the correctness of the DES library */
  /************************************************************************/
  if (!des_check ())
    {
      ERROR (-1, "DES functional test failed");
    }

  /*************************************/
  /* Check arguments and read datafile */
  /*************************************/
  /* If invalid number of arguments (including program name), exit with error
   * message. */
  if (argc != 3)
    {
      ERROR (-1, "usage: ta <datafile> <nexp>\n");
    }
  /* Number of experiments to use is argument #2, convert it to integer and
   * store the result in variable n. */
  n = atoi (argv[2]);
  if (n < 1)      /* If invalid number of experiments. */
    {
      ERROR (-1,
       "number of experiments to use (<nexp>) shall be greater than 1 (%d)",
       n);
    }
  read_datafile (argv[1],  /* Name of data file is argument #1. */
     n    /* Number of experiments to use. */
    );

  /*****************************************************************************
   * Compute the Hamming weight of output of first (leftmost) SBox during last *
   * round, under the assumption that the last round key is all zeros.         *
   *****************************************************************************/
  /* Undoes the final permutation on cipher text of n-th experiment. */
  r16l16 = des_ip (ct[n - 1]);
  /* Extract right half (strange naming as in the DES standard). */
  l16 = des_right_half (r16l16);
  /* Compute output of SBoxes during last round of first experiment, assuming
   * the last round key is all zeros. */
  sbo = des_sboxes (des_e (l16) ^ UINT64_C (0));  /* R15 = L16, K16 = 0 */
  /* Compute and print Hamming weight of output of first SBox (mask the others). */
  printf ("Hamming weight: %d\n",
    hamming_weight (sbo & UINT64_C (0xf0000000)));

  /************************************
   * Compute and print average timing *
   ************************************/
  sum = 0.0;      /* Initializes the accumulator for the sum of timing measurements. */
  for (i = 0; i < n; i++)  /* For all n experiments. */
    {
      sum = sum + t[i];    /* Accumulate timing measurements. */
    }
  /* Compute and print average timing measurements. */
  printf ("Average timing: %f\n", sum / (double) (n));
=======
  ///*****************************************************************************
  // * Compute the Hamming weight of output of first (leftmost) SBox during last *
  // * round, under the assumption that the last round key is all zeros.         *
  // *****************************************************************************/
  ///* Undoes the final permutation on cipher text of n-th experiment. */
  //r16l16 = des_ip (ct[n - 1]);
  ///* Extract right half (strange naming as in the DES standard). */
  //l16 = des_right_half (r16l16);
  ///* Compute output of SBoxes during last round of first experiment, assuming
  // * the last round key is all zeros. */
  //sbo = des_sboxes (des_e (l16) ^ UINT64_C (0));  /* R15 = L16, K16 = 0 */
  ///* Compute and print Hamming weight of output of first SBox (mask the others). */
  //printf ("Hamming weight: %d\n",
  //  hamming_weight (sbo & UINT64_C (0xf0000000)));

  ///************************************
  // * Compute and print average timing *
  // ************************************/
  //sum = 0.0;      /* Initializes the accumulator for the sum of timing measurements. */
  //for (i = 0; i < n; i++)  /* For all n experiments. */
  //  {
  //    sum = sum + t[i];    /* Accumulate timing measurements. */
  //  }
  ///* Compute and print average timing measurements. */
  //printf ("Average timing: %f\n", sum / (double) (n));

  
  /******************************************************************************
   * Statically finds out the key used during one round
   ******************************************************************************/

  uint64_t round_key = 0;
  uint64_t mask = UINT64_C(0x3f);
  int shift;
  int i_m;
  int key_i;
  uint64_t input; // input of one sbox
  int k;
  int ct_j;
  pcc_context ctx;

  for (shift = 1; shift <= 8; shift++)
  {
      double pearson[64] = {1};
      i_m = 0;

      for (key_i = 0; key_i < 64; key_i++)
      {
          uint64_t key = ((uint64_t) key_i) << (8-shift)*6;
          int hwt[n];
          uint64_t sbot[n];
          ctx = pcc_init(5);

          for (ct_j = 0; ct_j < n; ct_j++)
          {
              input = (( des_e( des_right_half( des_ip( ct[ct_j]))) ^ key ) >> (8-shift)*6) & mask; // 0x000000...abcdef
              printf("The SBox input is %016" PRIx64 "\n", input);
              sbot[ct_j] = des_sbox(shift, input);
              hwt[ct_j] = hamming_weight( sbot[ct_j]);
              pcc_insert_x(ctx, t[ct_j]);
              pcc_insert_y(ctx, hwt[ct_j], t[ct_j]);
          }
          pcc_consolidate(ctx);
          
          for (k = 0; k < 5; k++)
          {
              pearson[key_i] *= pcc_get_pcc(ctx, k);
          }
          pcc_free(ctx);
          i_m = (pearson[key_i] > pearson[i_m]) ? key_i : i_m;
      }
      round_key = round_key ^ (((uint64_t) i_m) << (8-shift)*6);
      printf ("The round key is %016" PRIx64 "\n", round_key);
  }






          


>>>>>>> 8e0bdb6ace88ef12cb3025c569eaa3ec9ae9926a

  /*******************************************************************************
   * Try all the 256 secret keys under the assumption that the last round key is *
   * all zeros.                                                                  *
   *******************************************************************************/
  /* If we are lucky, the secret key is one of the 256 possible with a all zeros
   * last round key. Let's try them all, using the known plain text - cipher text
   * pair as an oracle. */
  km = des_km_init ();    /* Initialize the key manager with no knowledge. */
  /* Tell the key manager that we 'know' the last round key (#16) is all zeros. */
  des_km_set_rk (km,    /* Key manager */
     16,    /* Round key number */
     1,    /* Force (we do not care about conflicts with pre-existing knowledge) */
     UINT64_C (0xffffffffffff),  /* We 'know' all the 48 bits of the round key */
     UINT64_C (0x000000000000)  /* The all zeros value for the round key */
    );
  /* Brute force attack with the knowledge we have and a known
   * plain text - cipher text pair as an oracle. */
  if (!brute_force (km, pt, ct[0]))
    {
      printf ("Too bad, we lose: the last round key is not all zeros.\n");
    }
  free (ct);      /* Deallocate cipher texts */
  free (t);      /* Deallocate timings */
  des_km_free (km);    /* Deallocate the key manager */
  return 0;      /* Exits with "everything went fine" status. */
}

void
read_datafile (char *name, int n)
{
  FILE *fp;      /* File descriptor for the data file. */
  int i;      /* Loop index */

  /* Open data file for reading, store file descriptor in variable fp. */
  fp = XFOPEN (name, "r");

  /* Read the first line and stores the value (plain text) in variable pt. If
   * read fails, exit with error message. */
  if (fscanf (fp, "%" PRIx64, &pt) != 1)
    {
      ERROR (-1, "cannot read plain text");
    }

  /* Allocates memory to store the cipher texts and timing measurements. Exit
   * with error message if memory allocation fails. */
  ct = XCALLOC (n, sizeof (uint64_t));
  t = XCALLOC (n, sizeof (double));

  /* Read the n experiments (cipher text and timing measurement). Store them in
   * the ct and t arrays. Exit with error message if read fails. */
  for (i = 0; i < n; i++)
    {
      if (fscanf (fp, "%" PRIx64 " %lf", &(ct[i]), &(t[i])) != 2)
        {
          ERROR (-1, "cannot read cipher text and/or timing measurement");
        }
    }
}

int
brute_force (des_key_manager km, uint64_t pt, uint64_t ct)
{
  uint64_t dummy, key, ks[16];

  des_km_init_for_unknown (km);  /* Initialize the iterator over unknown bits */
  do        /* Iterate over the possible keys */
    {
      key = des_km_get_key (km, &dummy);  /* Get current key, ignore the mask */
      des_ks (ks, key);    /* Compute key schedule with current key */
      if (des_enc (ks, pt) == ct)  /* If we are lucky... cheers. */
        {
          printf ("%016" PRIx64 "\n", key);
          return 1;    /* Stop iterating and return success indicator. */
        }
    }
  while (des_km_for_unknown (km));  /* Continue until we tried them all */
  return 0;      /* Return failure indicator. */
}

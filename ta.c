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
#include <math.h>

#include <utils.h>
#include <des.h>
#include <km.h>
#include <pcc.h>    /* To use the Pearson Correlation Coefficient */

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

/* Retrieve the round key i given the ciphertext R(i-1) and assuming the IP is already undone
 */

uint64_t round_key (uint64_t *ct, double *t, int n);

int
main (int argc, char **argv)
{
  int n;              /* Required number of experiments. */
  int i;              /* Loop index. */
  des_key_manager km; /* Key manager. */
  uint64_t *ct16;     /* Unfolded ciphertexts */
  uint64_t k16;       /* 16th round key */

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
  
  ct16 = XCALLOC (n, sizeof (uint64_t));

  for (i = 0; i < n; i++)
  {
      ct16[i] = des_ip(ct[i]);
  }

  k16 = round_key(ct16, t, n);

  printf("The key #16 is thought to be %" PRIx64 "\n", k16);

  uint64_t *l15;

  l15 = XCALLOC (n, sizeof (uint64_t));





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
     (uint64_t) k16  /* The all zeros value for the round key */
    );
  /* Brute force attack with the knowledge we have and a known
   * plain text - cipher text pair as an oracle. */
  if (!brute_force (km, pt, ct[0]))
    {
      printf ("Too bad, we lose: the last round key is not %" PRIx64".\n", k16);
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

uint64_t
round_key (uint64_t *ct, double *t, int n)
{
  /******************************************************************************
   * Statically finds out the key used during one round
   ******************************************************************************/

  uint64_t round_key = 0; /* The key we're interested in, 48 bits */
  uint64_t mask = UINT64_C(0x3f); /* The mask applied on the input of SBox ..111111 */
  int sbox_k; /* The SBox # we consider */
  pcc_context ctx; /* The Pearson context */

  for (sbox_k = 1; sbox_k <= 8; sbox_k++) /* For each SBox */
  {
      double pearson[64] ; /* Reset the PCCs */
      int key_i; /* The 6-bit key we consider */
      int i_m = 0; /* Reset the argmax */

      for (key_i = 0; key_i < 64; key_i++) /* For each 6-bit key */
      {
          uint64_t key = ((uint64_t) key_i) << (8-sbox_k)*6; /* We generate the key fitting the SBox # */
          double time_clusters[5][n]; /* Time clusters, depending ont the HW */
          int cluster_size[5] = {0}; /* Clusters size */
          int ct_j; /* The ciphertext number */
          
          ctx = pcc_init(4); /* Initialize the Pearson context */

          for (ct_j = 0; ct_j < n; ct_j++) /* For each ciphertext */
          {
              uint64_t sb_input = ((des_e(des_right_half(ct[ct_j])) ^ key) >> (8-sbox_k)*6) & mask; /* Input ciphering and masking */
              uint64_t sb_output = des_sbox(sbox_k, sb_input); /* SBox #sbox_k output */
              int hw = hamming_weight(sb_output); /* HW computation */
              time_clusters[hw][cluster_size[hw]] = t[ct_j]; /* We cluster the time taken according to HW */
              cluster_size[hw] += 1; /* We keep track of the cluster sizes */
          }

          int min_cluster_size = n; /* Minimum cluster size */
          int p; /* Loop index */
          int q; /* Loop index */
          for (p = 0; p < 5; p++) /* We compute the minimum cluster size */
          {
              min_cluster_size = (cluster_size[p] < min_cluster_size) ? cluster_size[p] : min_cluster_size;
          }

          for (p = 0; p < min_cluster_size; p++) /* We insert the random variable values into the PCC context ctx */
          {
              pcc_insert_x(ctx, time_clusters[0][p]); /* We use the HW=0 as a reference */
              
              for (q = 0; q < 4; q++)
              {
                  pcc_insert_y(ctx, q, time_clusters[q+1][p]);
              }
          }
          pcc_consolidate(ctx);
          pearson[key_i] = 0;
          
          for (q = 0; q < 4; q++)
          {
              pearson[key_i] += pcc_get_pcc(ctx, q); /* Average of the PCCs */

          }
          pearson[key_i] /= 4;
          pcc_free(ctx); /* We free the context for later use */
          i_m = (pearson[key_i] > pearson[i_m]) ? key_i : i_m; /* We keep the max pcc index */

      } 
      
      round_key = round_key | (((uint64_t) i_m) << (8-sbox_k)*6); /* The round key is constructed SBox-by-Sbox */

  }
  return round_key;
}

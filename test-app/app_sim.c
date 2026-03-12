/* app_sim.c
 *
 * Test bare-metal boot-led-on application
 *
 * Copyright (C) 2025 wolfSSL Inc.
 *
 * This file is part of wolfBoot.
 *
 * wolfBoot is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfBoot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "target.h"

#include "wolfboot/wolfboot.h"
#ifdef WOLFBOOT_SELF_HEADER
#include "image.h"
#endif

#ifdef WOLFBOOT_TPM
#include "wolftpm/tpm2.h"
#include "wolftpm/tpm2_wrap.h"
#endif

#ifdef DUALBANK_SWAP
uint32_t hal_sim_get_dualbank_state(void);
#endif

#ifdef TARGET_sim

/* Matches all keys:
 *    - chacha (32 + 12)
 *    - aes128 (16 + 16)
 *    - aes256 (32 + 16)
 */
/* Longest key possible: AES256 (32 key + 16 IV = 48) */
char enc_key[] = "0123456789abcdef0123456789abcdef"
		 "0123456789abcdef";

#ifdef TEST_DELTA_DATA
static volatile char __attribute__((used)) garbage[TEST_DELTA_DATA] = {0x01, 0x02, 0x03, 0x04 };

#endif

void hal_init(void);

#ifdef WOLFBOOT_TPM

#define TPM2_DEMO_STORAGE_KEY_HANDLE 0x81000200
static const char gStorageKeyAuth[] = "ThisIsMyStorageKeyAuth";
static const char gAiKeyAuth[] =      "ThisIsMyAiKeyAuth";

int getPrimaryStorageKey(WOLFTPM2_DEV* pDev, WOLFTPM2_KEY* pStorageKey){
    int rc;
    TPM_HANDLE handle = TPM2_DEMO_STORAGE_KEY_HANDLE;

    rc = wolfTPM2_ReadPublicKey(pDev, pStorageKey, handle);
    if (rc != 0) {
        /* Create primary storage key */
        rc = wolfTPM2_CreateSRK(pDev, pStorageKey, TPM_ALG_RSA,
            (byte*)gStorageKeyAuth, sizeof(gStorageKeyAuth)-1);
    } else {
        /* specify auth password for storage key */
        pStorageKey->handle.auth.size = sizeof(gStorageKeyAuth)-1;
        XMEMCPY(pStorageKey->handle.auth.buffer, gStorageKeyAuth,
                pStorageKey->handle.auth.size);
    }

    if ( rc != 0 ) {
        printf("Loading SRK: Storage failed\n");
    }
    else {
        printf("Loading SRK: Storage 0x%x (%d bytes)\n",
        (word32)pStorageKey->handle.hndl, pStorageKey->pub.size);
    }

    return rc;
}

#endif

int do_cmd(const char *cmd)
{
    if (strcmp(cmd, "powerfail") == 0) {
        return 1;
    }
    /* forces a bad write of the boot partition to trigger and test the
     * emergency fallback feature */
    if (strcmp(cmd, "emergency") == 0) {
        return 1;
    }
    if (strcmp(cmd, "get_version") == 0) {
        printf("%d\n", wolfBoot_current_firmware_version());
        return 0;
    }
    if (strcmp(cmd, "get_state") == 0) {
        uint8_t st = 0;
        wolfBoot_get_partition_state(PART_UPDATE, &st);
        printf("%02x\n", st);
        return 0;
    }
    if (strcmp(cmd, "success") == 0) {
        wolfBoot_success();
        return 0;
    }
#ifdef DUALBANK_SWAP
    if (strcmp(cmd, "get_swap_state") == 0) {
        printf("%u\n", hal_sim_get_dualbank_state());
        return 0;
    }
#endif
    if (strcmp(cmd, "update_trigger") == 0) {
#if EXT_ENCRYPTED
        wolfBoot_set_encrypt_key((uint8_t *)enc_key,(uint8_t *)(enc_key +  32));
#endif
        wolfBoot_update_trigger();
        return 0;
    }
    if (strcmp(cmd, "reset") == 0) {
        exit(0);
    }
    if (strncmp(cmd, "get_tlv",7) == 0) {
        /* boot partition and skip the image header offset (8 bytes) */
        uint8_t* imageHdr = (uint8_t*)WOLFBOOT_PARTITION_BOOT_ADDRESS + IMAGE_HEADER_OFFSET;
        uint8_t* ptr = NULL;
        uint16_t tlv = 0x34; /* default */
        int size;
        int i;

        const char* tlvStr = strstr(cmd, "get_tlv=");
        if (tlvStr) {
            tlvStr += strlen("get_tlv=");
            tlv = (uint16_t)atoi(tlvStr);
        }

        size = wolfBoot_find_header(imageHdr, tlv, &ptr);
        if (size > 0 && ptr != NULL) {
            /* From here, the value 0xAABBCCDD is at ptr */
            printf("TLV 0x%x: found (size %d):\n", tlv, size);
            for (i=0; i<size; i++) {
                printf("%02X", ptr[i]);
            }
            printf("\n");
            return 0;
        } else {
            printf("TLV 0x%x: not found!\r\n", tlv);
        }
    }
#ifdef WOLFBOOT_SELF_HEADER
    if (strcmp(cmd, "verify_self") == 0) {
        struct wolfBoot_image img;
        int                   ret;

        printf("=== Self-Header Verification Test ===\n");

        /* Open bootloader image using persisted self-header */
        ret = wolfBoot_open_self(&img);
        if (ret != 0) {
            printf("FAIL: wolfBoot_open_self returned %d\n", ret);
            return -1;
        }
        printf("open_self: OK (fw_size=%u, part=%d)\n", (unsigned)img.fw_size,
               img.part);

        /* Verify integrity (hash check) */
        ret = wolfBoot_verify_integrity(&img);
        if (ret != 0) {
            printf("FAIL: wolfBoot_verify_integrity returned %d\n", ret);
            return -1;
        }
        printf("verify_integrity: OK\n");

        /* Verify authenticity (signature check) */
        ret = wolfBoot_verify_authenticity(&img);
        if (ret != 0) {
            printf("FAIL: wolfBoot_verify_authenticity returned %d\n", ret);
            return -1;
        }
        printf("verify_authenticity: OK\n");

        printf("=== Self-header verification PASSED ===\n");
        return 0;
    }
#endif
#ifdef WOLFBOOT_TPM
    if (strcmp(cmd, "attestation") == 0) {
        WOLFTPM2_DEV dev;
        TPMS_ATTEST attestedData;
        WOLFTPM2_CAPS caps;
        WOLFTPM2_SESSION tpmSession;
        TPMT_PUBLIC publicTemplate;
        WOLFTPM2_KEY aikKey;
        WOLFTPM2_KEY storage; /* SRK */
        union {
        Quote_In quoteAsk;
        byte maxInput[MAX_COMMAND_SIZE];
        } cmdIn;
        union {
        Quote_Out quoteResult;
        byte maxOutput[MAX_RESPONSE_SIZE];
        } cmdOut;
        int rc;

        printf("=== Attestation Test ===\n");

        XMEMSET(&tpmSession, 0, sizeof(tpmSession));
        XMEMSET(&storage, 0, sizeof(storage));
        XMEMSET(&aikKey, 0, sizeof(aikKey));
        
        rc = wolfTPM2_Init(&dev, NULL, NULL);
        if (rc == 0)  {
        /* Get device capabilities + options */
        rc = wolfTPM2_GetCapabilities(&dev, &caps);
        }
        if (rc == 0) {
            printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
            "FIPS 140-2 %d, CC-EAL4 %d\n",
            caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
            caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
        } else {
            printf("GetCapabilities failed\n");
            return -1;
        }

        /* Generate or Read Storage Root Key */
        rc = getPrimaryStorageKey(&dev, &storage);

        if ( rc == 0 ) {
            /* Generate AIK */
            printf("Creating new key...\n");
            rc = wolfTPM2_CreateAndLoadAIK(&dev, &aikKey, TPM_ALG_RSA,
                                           &storage,  (byte*)gAiKeyAuth, sizeof(gAiKeyAuth)-1);
        }

        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_CreateAndLoadAIK failed\n");
            return -1;
        } else {
            printf("New key created and loaded (pub %d bytes)\n",
            aikKey.pub.size);
        }

        /* Set the handle of AIK */ 
        wolfTPM2_SetAuthHandle(&dev, 0, &aikKey.handle); 

        /* Prepare Quote request */
        XMEMSET(&cmdIn.quoteAsk, 0, sizeof(cmdIn.quoteAsk));
        XMEMSET(&cmdOut.quoteResult, 0, sizeof(cmdOut.quoteResult));
        cmdIn.quoteAsk.signHandle = aikKey.handle.hndl;
        cmdIn.quoteAsk.inScheme.scheme = TPM_ALG_RSASSA;
        cmdIn.quoteAsk.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
        cmdIn.quoteAsk.qualifyingData.size = 0; /* optional */
        /* Choose PCR for signing */
        TPM2_SetupPCRSel(&cmdIn.quoteAsk.PCRselect, TPM_ALG_SHA256, 16);

        rc = TPM2_Quote(&cmdIn.quoteAsk, &cmdOut.quoteResult);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_Quote failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            return -1;
        }
        printf("Quote success\n");

        rc = TPM2_ParseAttest(&cmdOut.quoteResult.quoted, &attestedData);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_Packet_ParseAttest failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
            return -1;
        }
        if (attestedData.magic != TPM_GENERATED_VALUE) {
            printf("\tError, attested data not generated by the TPM = 0x%X\n",
            attestedData.magic);
            return -1;
        }
        else {
            printf("TPM with signature attests (type 0x%x):\n", attestedData.type);
            printf("\tTPM signed %lu count of PCRs\n",
                (unsigned long)attestedData.attested.quote.pcrSelect.count);
#ifdef DEBUG_WOLFTPM
            printf("\tPCR digest:\n");
            TPM2_PrintBin(attestedData.attested.quote.pcrDigest.buffer,
                attestedData.attested.quote.pcrDigest.size);
            printf("\tTPM generated signature:\n");
            TPM2_PrintBin(cmdOut.quoteResult.signature.signature.rsassa.sig.buffer,
                cmdOut.quoteResult.signature.signature.rsassa.sig.size);
#endif
        }

        rc = wolfTPM2_Cleanup(&dev);
        if (rc != TPM_RC_SUCCESS) {
            printf("Failed to clean up\n");
            return -1;
        }

        return 0;
    }
#endif
    /* wrong command */
    return -1;
}

int main(int argc, char *argv[]) {

    int i;
    int ret;

    hal_init();

    for (i = 1; i < argc; ++i) {
        ret = do_cmd(argv[i]);
        if (ret < 0)
            return -1;
        i+= ret;
    }
    return 0;

}
#endif /** TARGET_sim **/

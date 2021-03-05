#include <iostream>

#include <nss.h>
#include <nss/secmodt.h>
#include <nspr/nspr.h>
#include <nss/pkcs11t.h>
#include <nss/pk11pub.h>
#include <nspr/prtypes.h>
#include <nss/secmod.h>


static char *password_passthrough(PK11SlotInfo *slot, PRBool retry, void *arg)
{
  /* give up if 1) no password was supplied, or 2) the password has already
   * been rejected once by this token. */
  if (retry || (arg == nullptr)) {
    return nullptr;
  }
  return strdup((char *)arg);
}

int main( int argc, char *argv[] )
{
    uint32_t flags = NSS_INIT_READONLY
                                   | NSS_INIT_FORCEOPEN
                                   | NSS_INIT_NOROOTINIT
                                   | NSS_INIT_OPTIMIZESPACE
                                   | NSS_INIT_PK11RELOAD;

    NSSInitParameters parameters = { 0 };
    parameters.length =  sizeof (parameters);

    auto nss_ctx = NSS_InitContext("/etc/pki/nssdb", "", "", SECMOD_DB, &parameters,
                                    flags);


    PK11_SetPasswordFunc(password_passthrough);

    std::cout << "<<<<<< DEFAULT MODULES >>>>>>>" << "\n";
    SECMODModuleList * mod_list = SECMOD_GetDefaultModuleList();
    SECMODModuleList * mod_list_item;

    for (mod_list_item = mod_list; mod_list_item != nullptr;
                                   mod_list_item = mod_list_item->next) {
        if (mod_list_item->module->commonName )
            std::cout << "common name:" << mod_list_item->module->commonName << "\n";

        if (mod_list_item->module->dllName)
            std::cout << "dll name: "<< mod_list_item->module->dllName << "\n";
    }

    std::cout << "<<<<<< DEAD MODULES >>>>>>>" << "\n";
    mod_list = SECMOD_GetDeadModuleList();
    for (mod_list_item = mod_list; mod_list_item != nullptr;
                                    mod_list_item = mod_list_item->next) {
        if (mod_list_item->module->commonName )
            std::cout << "common name:" << mod_list_item->module->commonName << "\n";

        if (mod_list_item->module->dllName)
            std::cout << "dll name: "<< mod_list_item->module->dllName << "\n";
    }

    std::cout << "<<<<<< DB MODULES >>>>>>>" << "\n";
    mod_list = SECMOD_GetDBModuleList();
    for (mod_list_item = mod_list; mod_list_item != nullptr;
                                    mod_list_item = mod_list_item->next) {
        if (mod_list_item->module->commonName)
            std::cout << "common name:" << mod_list_item->module->commonName << "\n";

        if (mod_list_item->module->dllName)
            std::cout << "dll name: "<< mod_list_item->module->dllName << "\n";
    }

    PK11SlotList* list = PK11_GetAllTokens(CKM_INVALID_MECHANISM, PR_FALSE, PR_TRUE, nullptr);

    if (list == nullptr) {
        return 0;
    }

    std::cout << "<<<<<< TOKENS LIST >>>>>>>" << "\n";
    PK11SlotListElement *le;
    PK11SlotInfo *slot = nullptr;

    for (PK11SlotListElement * p = list->head; p; p = p->next) {
        CK_SLOT_INFO slInfo;
        PK11_GetSlotInfo(p->slot, &slInfo);
        PK11SlotInfo * slot = PK11_ReferenceSlot(p->slot);
        const char* slot_name = PK11_GetTokenName(slot);

        if (slot_name)
            std::cout << slot_name << "\n";

        if (slInfo.slotDescription)
            std::cout << slInfo.slotDescription << "\n";
    }

    std::cout << "<<<<<< SLOT LIST >>>>>>>" << "\n";
    for (le = list->head; le; le = le->next) {
        CK_SLOT_INFO slInfo;

        slInfo.flags = 0;
        auto rv = PK11_GetSlotInfo(le->slot, &slInfo);

        if (slInfo.manufacturerID)
            std::cout << slInfo.manufacturerID << "\n";

        if (slInfo.slotDescription)
            std::cout << slInfo.slotDescription << "\n";

        if (rv == SECSuccess && (slInfo.flags & CKF_REMOVABLE_DEVICE)) {
            slot = PK11_ReferenceSlot(le->slot);
            break;
        }
    }

    PK11_FreeSlotList(list);

    NSS_ShutdownContext(nss_ctx);

    return 0;
}

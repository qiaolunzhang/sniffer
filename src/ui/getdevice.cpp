#include "getdevice.h"

getdevice::getdevice()
{

}

getdevice::~getdevice()
{

}

void getdevice::set_all_device()
{
    struct if_nameindex *if_ni, *i;
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        device_all = new char *[1];
        device_all[0] = "error";
        return;
    }
    device_count = sizeof(if_ni) / sizeof(if_ni[0]);
    device_all = new char *[device_count];
    int device_index = 0;
    for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
        device_all[device_index] = i->if_name;
        device_index = device_index + 1;
    }
    // there is a question, is device_count bigger than device_index?
    device_count = device_index;
}

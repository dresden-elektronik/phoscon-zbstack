#include "port_locate.h"
#include "zb_utils.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>

/* A property of the serial service, or with `parents` of the nearest entry above it that has one: the USB interface or
   device the service hangs from, measured with ioreg for the CDC ConBee II and the FTDI sticks alike. */
static CFTypeRef darwinProperty(io_object_t service, CFStringRef key, int parents)
{
    if (!parents)
        return IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);

    return IORegistryEntrySearchCFProperty(service, kIOServicePlane, key, kCFAllocatorDefault,
                                           kIORegistryIterateRecursively | kIORegistryIterateParents);
}

static int darwinString(io_object_t service, CFStringRef key, int parents, char *out, uint32_t capacity)
{
    CFTypeRef value = darwinProperty(service, key, parents);
    int ok = 0;

    out[0] = 0;

    if (value == 0)
        return 0;

    if (CFGetTypeID(value) == CFStringGetTypeID())
        ok = CFStringGetCString((CFStringRef)value, out, (CFIndex)capacity, kCFStringEncodingUTF8) ? 1 : 0;

    CFRelease(value);
    return ok;
}

static uint16_t darwinNumber(io_object_t service, CFStringRef key)
{
    CFTypeRef value = darwinProperty(service, key, 1);
    int32_t number = 0;

    if (value == 0)
        return 0;

    if (CFGetTypeID(value) == CFNumberGetTypeID())
        (void)CFNumberGetValue((CFNumberRef)value, kCFNumberSInt32Type, &number);

    CFRelease(value);
    return (uint16_t)number;
}

/* Every IOSerialBSDClient with a USB serial number above it: its callout node, which IOKit names as it creates it. */
uint32_t PortLocate_EachPlatform(PortLocate_Visit visit, void *context)
{
    PortLocate_Candidate candidate;
    CFMutableDictionaryRef matching;
    io_iterator_t services;
    io_object_t service;
    uint32_t count = 0;

    if (visit == 0)
        return 0;

    matching = IOServiceMatching(kIOSerialBSDServiceValue);

    if (matching == 0 || IOServiceGetMatchingServices(MACH_PORT_NULL, matching, &services) != KERN_SUCCESS)
        return 0;

    while ((service = IOIteratorNext(services)) != 0)
    {
        Zb_memset(&candidate, 0, (uint32_t)sizeof candidate);

        if (darwinString(service, CFSTR(kIOCalloutDeviceKey), 0, candidate.device, (uint32_t)sizeof candidate.device)
                && darwinString(service, CFSTR("USB Serial Number"), 1, candidate.serial,
                                (uint32_t)sizeof candidate.serial))
        {
            (void)darwinString(service, CFSTR("USB Product Name"), 1, candidate.product,
                               (uint32_t)sizeof candidate.product);
            candidate.vendorId = darwinNumber(service, CFSTR("idVendor"));
            candidate.productId = darwinNumber(service, CFSTR("idProduct"));
            candidate.present = 1;
            visit(context, &candidate);
            count++;
        }

        IOObjectRelease(service);
    }

    IOObjectRelease(services);
    return count;
}

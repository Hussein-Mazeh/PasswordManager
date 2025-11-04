package toggle

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation -framework Security -framework CoreFoundation

#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdlib.h>

static int passman_bio_prompt(const char *cReason) {
	@autoreleasepool {
		NSString *reason = cReason ? [[NSString alloc] initWithUTF8String:cReason] : @"Authenticate to continue";
		if (!reason) {
			reason = @"Authenticate to continue";
		}

		LAContext *context = [[LAContext alloc] init]; //represents the biometric authentication session(main class that allows touchID on macOS)
		if (!context) {
			return -100;
		}

		NSError *canError = nil;
		if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&canError]) {
			return canError ? (int)[canError code] : -101;
		}

		dispatch_semaphore_t sema = dispatch_semaphore_create(0);

		__block BOOL success = NO;
		__block NSError *evalError = nil;

		[context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
		        localizedReason:reason
		                  reply:^(BOOL evaluated, NSError * _Nullable error) {
		                      success = evaluated;
		                      evalError = error;
		                      dispatch_semaphore_signal(sema);
		                  }]; // Main block that starts the Touch ID prompt and returns success if everything worked correctly

		dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60 * NSEC_PER_SEC)); //Wait for 60 seconds for the callback, then invalidate
		long waitResult = dispatch_semaphore_wait(sema, timeout);
		[context invalidate];

		if (waitResult != 0) {
			return -103;
		}
		if (success) {
			return 0;
		}
		return evalError ? (int)[evalError code] : -104;
	}
}
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

const defaultReason = "Authenticate with Touch ID to continue"

// Authenticate prompts the user with Touch ID before continuing.
func Authenticate(reason string) error {
	if strings.TrimSpace(reason) == "" {
		reason = defaultReason
	}
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	code := int(C.passman_bio_prompt(cReason))
	if code == 0 {
		return nil
	}
	return fmt.Errorf("biometric authentication failed (code %d)", code)
}

// This file is written in objective-C because the access to Apple's LocalAuthentication framework is exposed
// only in Objective-C and aren't written in Go

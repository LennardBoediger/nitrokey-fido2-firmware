#include "user_feedback.h"

#include "bsp.h"
#include "gpio.h"
#include "log.h"

#include "u2f_compat.h"

static bool first_request_accepted = false;

/**
 * Confirm user presence by getting touch button, or device insertion.
 * Returns: '0' - user presence confirmed, '1' otherwise
 */
static int8_t _u2f_get_user_feedback(BUTTON_STATE_T target_button_state, bool blink)
{
    uint32_t t;
    uint8_t user_presence = 0;

    // Accept first request in the first SELF_ACCEPT_MAX_T_MS after power cycle.
    // Solution only for a short touch request, not for configuration changes.
    if (!first_request_accepted && (get_ms() < SELF_ACCEPT_MAX_T_MS)
        && (target_button_state == BST_PRESSED_REGISTERED) ){
        first_request_accepted = true;
        stop_blinking();
        printf1(TAG_BUTTON, "first_request_accepted\n");
        return 0;
    }

    // Auto touch for BST_PRESSED_CONSUMED_ACTIVE state.
    // For the short activation period BUTTON_VALID_CONSUMED_T_MS after a touch is consumed, only simple actions
    if (button_get_press() && target_button_state == BST_PRESSED_REGISTERED) {
        printf1(TAG_BUTTON, "Touch active\n");
        return 0;
    }

    // Reject all requests, if device is not ready yet for touch button feedback,
    // or if the touch is already consumed
    if (button_press_is_consumed() || button_get_press_state() < BST_META_READY_TO_USE) {
        printf1(TAG_BUTTON, "Touch consumed or button not ready\n");
        return 1;
    }

    if (blink == true && led_is_blinking() == false)
        led_blink(50, LED_BLINK_PERIOD);
    else if (blink == false)
        stop_blinking();

    t = get_ms();
    while(button_get_press_state() != target_button_state)	// Wait to push button
    {
        led_blink_manager();                               // Run led driver to ensure blinking
        button_manager();                                 // Run button driver
        if (get_ms() - t > U2F_MS_USER_INPUT_WAIT    // 100ms elapsed without button press
            && !button_press_in_progress())			// Button press has not been started
            break;                                    // Timeout
        u2f_delay(10);
#ifdef FAKE_TOUCH
        if (get_ms() - t > 1010) break; //1212
#endif
    }

#ifndef FAKE_TOUCH
    if (button_get_press_state() == target_button_state)
#else //FAKE_TOUCH
        if (true)
#endif
    {
        printf1(TAG_BUTTON, "Touch registered\n");
        // Button has been pushed in time
        user_presence = 1;
        button_press_set_consumed(target_button_state);
        stop_blinking();
#ifdef SHOW_TOUCH_REGISTERED
        //show short confirming animation
		t = get_ms();
		while(get_ms() - t < 110){
			led_on();
			u2f_delay(12);
			led_off();
			u2f_delay(25);
		}
        stop_blinking();
#endif
    } else {                                          // Button hasnt been pushed within the timeout
        user_presence = 0;                                     // Return error code
    }


    return user_presence? 0 : 1;
}

int8_t u2f_get_user_feedback(){
    return _u2f_get_user_feedback(BST_PRESSED_REGISTERED, true);
}

int8_t u2f_get_user_feedback_extended_wipe(){
    return _u2f_get_user_feedback(BST_PRESSED_REGISTERED_EXT, true);
}

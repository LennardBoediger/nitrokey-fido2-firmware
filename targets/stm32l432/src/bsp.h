/*
 * Copyright (c) 2016, Conor Patrick
 * Copyright (c) 2018, Nitrokey UG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef BSP_H_
#define BSP_H_

#include <stdint.h>
#include "app.h"
#include "device.h"
#include "stm32l4xx_ll_gpio.h"

/*
 * U2F_BUTTON_RESET is a MTPM pin. Requires HIGH state to keep
 * NORMAL power mode on MTCH101
 * */

#define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))

extern uint8_t LED_STATE;

#define LED_ON()                 { LED_STATE = 1; }
#define LED_OFF()                { LED_STATE = 0; }
#define BUTTON_RESET_ON()        {}
#define BUTTON_RESET_OFF()       {}
#define IS_LED_ON()              (LED_STATE == 1)

#define get_ms()                  millis()


#endif /* BSP_H_ */

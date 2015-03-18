/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors. 
 *  Some rights reserved. See LICENSE, AUTHORS.
 */


#ifndef __TRACEBOX_SCRIPT_H__
#define __TRACEBOX_SCRIPT_H__

#include "crafter.h"

Crafter::Packet *script_packet(std::string& cmd);
int script_exec(const char*, int, char**);
int script_execfile(const char*, int, char**);

#endif

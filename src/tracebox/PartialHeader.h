/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors. 
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __PARTIALHEADER_H__
#define __PARTIALHEADER_H__

#include "crafter.h"

/* ICMP message can contains partial header information */

namespace Crafter {

	class PartialTCP: public Layer {
		void DefineProtocol();

		Constructor GetConstructor() const {
			return PartialTCP::PartialTCPConstFunc;
		};

		static Layer* PartialTCPConstFunc() {
			return NULL;
		};

		void Craft();

	public:
		PartialTCP(RawLayer& raw);
		~PartialTCP();
	};

};

#endif

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
		PartialTCP();

		void DefineProtocol();

		Constructor GetConstructor() const {
			return PartialTCP::PartialTCPConstFunc;
		};

		static Layer* PartialTCPConstFunc() {
			return new PartialTCP();
		};

		void Craft() { };

		std::string MatchFilter() const;

		void ReDefineActiveFields() {};

		static const byte FieldSrcPort = 0;
		static const byte FieldDstPort = 1;
		static const byte FieldSeqNumber = 2;

	public:
		enum { PROTO = 0x06ff };

		PartialTCP(RawLayer& raw);
		PartialTCP(PartialTCP &partial);
		~PartialTCP() { };

		void SetSrcPort(const short_word &value) {
			SetFieldValue(FieldSrcPort, value);
		}

		void SetDstPort(const short_word &value) {
			SetFieldValue(FieldDstPort, value);
		}

		void SetSeqNumber(const word &value) {
			SetFieldValue(FieldSeqNumber, value);
		}

		short_word GetSrcPort() const {
			return GetFieldValue<short_word>(FieldSrcPort);
		}

		short_word GetDstPort() const {
			return GetFieldValue<short_word>(FieldDstPort);
		}

		word GetSeqNumber() const {
			return GetFieldValue<short_word>(FieldSeqNumber);
		}

		const byte* GetRawPointer() const { return this->raw_data; };

		static void register_type();
	};

};

#endif

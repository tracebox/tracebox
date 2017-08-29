/**
 * Tracebox -- A middlebox detection tool
 *
 *  Copyright 2013-2015 by its authors.
 *  Some rights reserved. See LICENSE, AUTHORS.
 */

#ifndef __PACKETMODIFICATION_H__
#define __PACKETMODIFICATION_H__

#include "crafter.h"
#ifdef HAVE_LIBJSON
#include <json/json.h>
#endif
#ifdef HAVE_JSONC
#include <json-c/json.h>
#endif

#include <memory>

using namespace Crafter;

class Modification {
	/* Layer protocol where the modification occured. The protocol is as defined
	 * in Libcrafter.
	 */
	int layer_proto;

	/* Representation of the modification */
	std::string name;

	/* Offset compared to the start of the layer (in bits) */
	size_t offset;

	/* Length of the modification (in bits) */
	size_t len;

	/* Some private functions */
	std::string GetModifRepr() const;
	json_object* GetModifRepr_JSON() const;

protected:
	/* Field values helper */
	std::string field1_repr;
	std::string field2_repr;

public:
	Modification(int proto, std::string name, size_t offset, size_t len);
	Modification(int proto, const FieldInfo *f1, const FieldInfo *f2);
	Modification(const Layer *l1, const Layer *l2);

	int getOffset() const {
		return offset;
	}

	int GetOffsetBytes() const {
		return offset / 32;
	}

	size_t GetLength() const {
		return len;
	}

	std::string GetName() const {
		return name;
	}

	virtual ~Modification() {}

	virtual void Print(std::ostream& out = std::cout,
			bool verbose = false) const;

	virtual void Print_JSON(json_object *res, json_object *add,
			json_object *del, bool verbose = false) const;
};

struct Addition : public Modification {
	Addition(const Layer *l);

	virtual void Print(std::ostream& out, bool verbose = false) const;

	virtual void Print_JSON(json_object *res, json_object *add,
			json_object *del, bool verbose = false) const;
};

struct Deletion : public Modification {
	Deletion(const Layer *l);

	virtual void Print(std::ostream& out, bool verbose = false) const;

	virtual void Print_JSON(json_object *res, json_object *add,
			json_object *del, bool verbose = false) const;
};

struct PacketModifications : public std::vector<Modification *> {
	const std::shared_ptr<const Packet> orig;
	const std::shared_ptr<const Packet> modif;
	std::vector<const Layer*> extensions;
	bool partial;

	PacketModifications(const std::shared_ptr<Packet> orig,
			const Packet *modif, std::vector<const Layer*> &ext,
			bool partial=false) :
		orig(orig), modif(modif), extensions(ext), partial(partial) {}
	virtual ~PacketModifications();

	void Print(std::ostream& out = std::cout, bool verbose = false) const;

	static PacketModifications* ComputeModifications(
			const std::shared_ptr<Crafter::Packet> pkt,
			Crafter::Packet *rcv);

	virtual void Print_JSON(json_object *res, json_object *add,
			json_object *del, json_object **ext, bool verbose = false) const;
};

#endif

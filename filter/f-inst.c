/*
 *	Filters: Instructions themselves
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *	Copyright 2018 Maria Matejka <mq@jmq.cz>
 *	Copyright 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

/* Binary operators */
  INST(FI_ADD, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    res.val.i += v2.val.i;
    RESULT_OK;
  }
  INST(FI_SUBTRACT, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    res.val.i -= v2.val.i;
    RESULT_OK;
  }
  INST(FI_MULTIPLY, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    res.val.i *= v2.val.i;
    RESULT_OK;
  }
  INST(FI_DIVIDE, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    if (v2.val.i == 0) runtime( "Mother told me not to divide by 0" );
    res.val.i /= v2.val.i;
    RESULT_OK;
  }
  INST(FI_AND, 1, 1) {
    ARG(1,T_BOOL);
    if (res.val.i)
      LINE(2,0);
    else
      RESULT_OK;
  }
  INST(FI_OR, 1, 1) {
    ARG(1,T_BOOL);
    if (!res.val.i)
      LINE(2,0);
    else
      RESULT_OK;
  }
  INST(FI_PAIR_CONSTRUCT, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    uint u1 = v1.val.i;
    uint u2 = v2.val.i;
    if ((u1 > 0xFFFF) || (u2 > 0xFFFF))
      runtime( "Can't operate with value out of bounds in pair constructor" );
    RESULT(T_PAIR, i, (u1 << 16) | u2);
  }
  INST(FI_EC_CONSTRUCT, 2, 1) {
    ARG_ANY(1);
    ARG(2, T_INT);
    ECS;

    int check, ipv4_used;
    u32 key, val;

    if (v1.type == T_INT) {
      ipv4_used = 0; key = v1.val.i;
    }
    else if (v1.type == T_QUAD) {
      ipv4_used = 1; key = v1.val.i;
    }
    /* IP->Quad implicit conversion */
    else if (val_is_ip4(&v1)) {
      ipv4_used = 1; key = ipa_to_u32(v1.val.ip);
    }
    else
      runtime("Argument 1 of instruction FI_EC_CONSTRUCT must be integer or IPv4 address, got 0x%02x");

    val = v2.val.i;

    if (ecs == EC_GENERIC) {
      check = 0; RESULT(T_EC, ec, ec_generic(key, val));
    }
    else if (ipv4_used) {
      check = 1; RESULT(T_EC, ec, ec_ip4(ecs, key, val));
    }
    else if (key < 0x10000) {
      check = 0; RESULT(T_EC, ec, ec_as2(ecs, key, val));
    }
    else {
      check = 1; RESULT(T_EC, ec, ec_as4(ecs, key, val));
    }

    if (check && (val > 0xFFFF))
      runtime("Value %u > %u out of bounds in EC constructor", val, 0xFFFF);
  }

  INST(FI_LC_CONSTRUCT, 3, 1) {
    ARG(1, T_INT);
    ARG(2, T_INT);
    ARG(3, T_INT);
    RESULT(T_LC, lc, [[(lcomm) { v1.val.i, v2.val.i, v3.val.i }]]);
  }

  INST(FI_PATHMASK_CONSTRUCT, 0, 1) {
    ARG_ANY(1);
    COUNT(2);

    FID_NEW_BODY
      uint len = 0;
      uint dyn = 0;
      for (const struct f_inst *tt = f1; tt; tt = tt->next, len++)
	if (tt->fi_code != FI_CONSTANT)
	  dyn++;

      what->count = len;
    FID_ALL

    if (vstk.cnt < whati->count) /* TODO: make this check systematic */
      runtime("Construction of BGP path mask from %u elements must have at least that number of elements", whati->count);

    struct f_path_mask *pm = lp_alloc(fs->pool, sizeof(struct f_path_mask) + whati->count * sizeof(struct f_path_mask_item));
    for (uint i=0; i<whati->count; i++) {
#define pv vstk.val[vstk.cnt - whati->count + i]
      switch (pv.type) {
	case T_PATH_MASK_ITEM:
	  pm->item[i] = pv.val.pmi;
	  break;
	case T_INT:
	  pm->item[i] = (struct f_path_mask_item) {
	    .asn = pv.val.i,
	    .kind = PM_ASN,
	  };
	  break;
	default:
	  runtime( "Error resolving path mask template: value not an integer" );
      }
    }

    vstk.cnt -= whati->count;
    pm->len = whati->count;

    RESULT(T_PATH_MASK, path_mask, pm);
  }

/* Relational operators */

  INST(FI_NEQ, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    RESULT(T_BOOL, i, !val_same(&v1, &v2));
  }

  INST(FI_EQ, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    RESULT(T_BOOL, i, val_same(&v1, &v2));
  }

  INST(FI_LT, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    int i = val_compare(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "Can't compare values of incompatible types" );
    RESULT(T_BOOL, i, (i == -1));
  }

  INST(FI_LTE, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    int i = val_compare(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "Can't compare values of incompatible types" );
    RESULT(T_BOOL, i, (i != 1));
  }

  INST(FI_NOT, 1, 1) {
    ARG(1,T_BOOL);
    RESULT(T_BOOL, i, !v1.val.i);
  }

  INST(FI_MATCH, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    int i = val_in_range(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "~ applied on unknown type pair" );
    RESULT(T_BOOL, i, !!i);
  }

  INST(FI_NOT_MATCH, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    int i = val_in_range(&v1, &v2);
    if (res.val.i == F_CMP_ERROR)
      runtime( "!~ applied on unknown type pair" );
    RESULT(T_BOOL, i, !i);
  }

  INST(FI_DEFINED, 1, 1) {
    ARG_ANY(1);
    RESULT(T_BOOL, i, (v1.type != T_VOID) && !undef_value(v1));
  }

  INST(FI_TYPE, 1, 1) {
    ARG_ANY(1); /* There may be more types supporting this operation */
    switch (v1.type)
    {
      case T_NET:
	RESULT(T_ENUM_NETTYPE, i, v1.val.net->type);
	break;
      default:
	runtime( "Can't determine type of this item" );
    }
  }

  INST(FI_IS_V4, 1, 1) {
    ARG(1, T_IP);
    RESULT(T_BOOL, i, ipa_is_ip4(v1.val.ip));
  }

  /* Set to indirect value prepared in v1 */
  INST(FI_SET, 1, 0) {
    ARG_ANY(2);
    SYMBOL(1);
    if ((sym->class != (SYM_VARIABLE | v1.type)) && (v1.type != T_VOID))
    {
      /* IP->Quad implicit conversion */
      if ((sym->class == (SYM_VARIABLE | T_QUAD)) && val_is_ip4(&v1))
      {
	*(sym->val) = (struct f_val) {
	  .type = T_QUAD,
	  .val.i = ipa_to_u32(v1.val.ip),
	}; 
	break;
      }
      runtime( "Assigning to variable of incompatible type" );
    }
    *(sym->val) = v1;
  }

    /* some constants have value in a[1], some in *a[0].p, strange. */
  INST(FI_CONSTANT, 0, 1) {	/* integer (or simple type) constant, string, set, or prefix_set */
    FID_LINE_IN
      struct f_val val;
    FID_STRUCT_IN
      struct f_val val;
    FID_NEW_ARGS
    , const struct f_val val
    FID_NEW_BODY
      what->val = val;
    FID_POSTFIXIFY_BODY
      item->val = what->val;
    FID_SAME_BODY
      if (!val_same(&(f1->val), &(f2->val))) return 0;
    FID_DUMP_BODY
      debug("%svalue %s\n", INDENT, val_dump(&item->val));
    FID_ALL

    res = whati->val;
    RESULT_OK;
  }
  INST(FI_VARIABLE, 0, 1) {
    FID_STRUCT_IN
      const struct symbol *sym;
    FID_LINE_IN
      const struct symbol *sym;
      const struct f_val *valp;
    FID_NEW_ARGS
      , const struct symbol *sym
    FID_NEW_BODY
      what->sym = sym;
    FID_POSTFIXIFY_BODY
      item->valp = (item->sym = what->sym)->val;
    FID_SAME_BODY
      if (strcmp(f1->sym->name, f2->sym->name) || (f1->sym->class != f2->sym->class)) return 0;
    FID_DUMP_BODY
      switch (item->sym->class) {
	case SYM_CONSTANT_RANGE:
	  debug("%sconstant %s with value %s\n", INDENT, item->sym->name, val_dump(item->valp));
	  break;
	case SYM_VARIABLE_RANGE:
	  debug("%svariable %s with current value %s\n", INDENT, item->sym->name, val_dump(item->valp));
	  break;
	default:
	  bug("Symbol %s of type %d doesn't reference a value", item->sym->name, item->sym->class);
      }
    FID_ALL

    res = *whati->valp;
    RESULT_OK;
  }
  INST(FI_PRINT, 1, 0) {
    ARG_ANY(1);
    val_format(&(v1), &fs->buf);
  }
  INST(FI_CONDITION, 1, 0) {
    ARG(1, T_BOOL);
    if (res.val.i)
      LINE(2,0);
    else
      LINE(3,1);
  }
  INST(FI_PRINT_AND_DIE, 0, 0) {
    FID_POSTFIXIFY_BODY
    {
      uint opos = pos;
      FID_ALL

    ARG_ANY(1);

      FID_POSTFIXIFY_BODY
      if (opos < pos)
	dest->items[pos].flags |= FIF_PRINTED;
    }
    FID_ALL

    FRET(2);

    if ((fret == F_NOP || (fret != F_NONL && (what->flags & FIF_PRINTED))) &&
	!(fs->flags & FF_SILENT))
      log_commit(*L_INFO, &fs->buf);

    switch (fret) {
    case F_QUITBIRD:
      die( "Filter asked me to die" );
    case F_ACCEPT:
      /* Should take care about turning ACCEPT into MODIFY */
    case F_ERROR:
    case F_REJECT:	/* FIXME (noncritical) Should print complete route along with reason to reject route */
      return fret;	/* We have to return now, no more processing. */
    case F_NONL:
    case F_NOP:
      break;
    default:
      bug( "unknown return type: Can't happen");
    }
  }
  
  INST(FI_RTA_GET, 0, 1) {	/* rta access */
    {
      STATIC_ATTR;
      ACCESS_RTE;
      struct rta *rta = (*fs->rte)->attrs;

      switch (sa.sa_code)
      {
      case SA_FROM:	RESULT(sa.f_type, ip, rta->from); break;
      case SA_GW:	RESULT(sa.f_type, ip, rta->nh.gw); break;
      case SA_NET:	RESULT(sa.f_type, net, (*fs->rte)->net->n.addr); break;
      case SA_PROTO:	RESULT(sa.f_type, s, rta->src->proto->name); break;
      case SA_SOURCE:	RESULT(sa.f_type, i, rta->source); break;
      case SA_SCOPE:	RESULT(sa.f_type, i, rta->scope); break;
      case SA_DEST:	RESULT(sa.f_type, i, rta->dest); break;
      case SA_IFNAME:	RESULT(sa.f_type, s, rta->nh.iface ? rta->nh.iface->name : ""); break;
      case SA_IFINDEX:	RESULT(sa.f_type, i, rta->nh.iface ? rta->nh.iface->index : 0); break;

      default:
	bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
      }
    }
  }

  INST(FI_RTA_SET, 1, 0) {
    ACCESS_RTE;
    ARG_ANY(1);
    STATIC_ATTR;
    if (sa.f_type != v1.type)
      runtime( "Attempt to set static attribute to incompatible type" );

    f_rta_cow(fs);
    {
      struct rta *rta = (*fs->rte)->attrs;

      switch (sa.sa_code)
      {
      case SA_FROM:
	rta->from = v1.val.ip;
	break;

      case SA_GW:
	{
	  ip_addr ip = v1.val.ip;
	  neighbor *n = neigh_find(rta->src->proto, ip, NULL, 0);
	  if (!n || (n->scope == SCOPE_HOST))
	    runtime( "Invalid gw address" );

	  rta->dest = RTD_UNICAST;
	  rta->nh.gw = ip;
	  rta->nh.iface = n->iface;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	}
	break;

      case SA_SCOPE:
	rta->scope = v1.val.i;
	break;

      case SA_DEST:
	{
	  int i = v1.val.i;
	  if ((i != RTD_BLACKHOLE) && (i != RTD_UNREACHABLE) && (i != RTD_PROHIBIT))
	    runtime( "Destination can be changed only to blackhole, unreachable or prohibit" );

	  rta->dest = i;
	  rta->nh.gw = IPA_NONE;
	  rta->nh.iface = NULL;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	}
	break;

      case SA_IFNAME:
	{
	  struct iface *ifa = if_find_by_name(v1.val.s);
	  if (!ifa)
	    runtime( "Invalid iface name" );

	  rta->dest = RTD_UNICAST;
	  rta->nh.gw = IPA_NONE;
	  rta->nh.iface = ifa;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	}
	break;

      default:
	bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
      }
    }
  }

  INST(FI_EA_GET, 0, 1) {	/* Access to extended attributes */
    DYNAMIC_ATTR;
    ACCESS_RTE;
    ACCESS_EATTRS;
    {
      eattr *e = ea_find(*fs->eattrs, da.ea_code);

      if (!e) {
	/* A special case: undefined as_path looks like empty as_path */
	if (da.type == EAF_TYPE_AS_PATH) {
	  RESULT(T_PATH, ad, &null_adata);
	  break;
	}

	/* The same special case for int_set */
	if (da.type == EAF_TYPE_INT_SET) {
	  RESULT(T_CLIST, ad, &null_adata);
	  break;
	}

	/* The same special case for ec_set */
	if (da.type == EAF_TYPE_EC_SET) {
	  RESULT(T_ECLIST, ad, &null_adata);
	  break;
	}

	/* The same special case for lc_set */
	if (da.type == EAF_TYPE_LC_SET) {
	  RESULT(T_LCLIST, ad, &null_adata);
	  break;
	}

	/* Undefined value */
	res.type = T_VOID;
	RESULT_OK;
	break;
      }

      switch (e->type & EAF_TYPE_MASK) {
      case EAF_TYPE_INT:
	RESULT(da.f_type, i, e->u.data);
	break;
      case EAF_TYPE_ROUTER_ID:
	RESULT(T_QUAD, i, e->u.data);
	break;
      case EAF_TYPE_OPAQUE:
	RESULT(T_ENUM_EMPTY, i, 0);
	break;
      case EAF_TYPE_IP_ADDRESS:
	RESULT(T_IP, ip, *((ip_addr *) e->u.ptr->data));
	break;
      case EAF_TYPE_AS_PATH:
	RESULT(T_PATH, ad, e->u.ptr);
	break;
      case EAF_TYPE_BITFIELD:
	RESULT(T_BOOL, i, !!(e->u.data & (1u << da.bit)));
	break;
      case EAF_TYPE_INT_SET:
	RESULT(T_CLIST, ad, e->u.ptr);
	break;
      case EAF_TYPE_EC_SET:
	RESULT(T_ECLIST, ad, e->u.ptr);
	break;
      case EAF_TYPE_LC_SET:
	RESULT(T_LCLIST, ad, e->u.ptr);
	break;
      case EAF_TYPE_UNDEF:
	res.type = T_VOID;
	RESULT_OK;
	break;
      default:
	bug("Unknown dynamic attribute type");
      }
    }
  }

  INST(FI_EA_SET, 1, 0) {
    ACCESS_RTE;
    ACCESS_EATTRS;
    ARG_ANY(1);
    DYNAMIC_ATTR;
    {
      struct ea_list *l = lp_alloc(fs->pool, sizeof(struct ea_list) + sizeof(eattr));

      l->next = NULL;
      l->flags = EALF_SORTED;
      l->count = 1;
      l->attrs[0].id = da.ea_code;
      l->attrs[0].flags = 0;
      l->attrs[0].type = da.type | EAF_ORIGINATED | EAF_FRESH;

      switch (da.type) {
      case EAF_TYPE_INT:
	if (v1.type != da.f_type)
	  runtime( "Setting int attribute to non-int value" );
	l->attrs[0].u.data = v1.val.i;
	break;

      case EAF_TYPE_ROUTER_ID:
	/* IP->Quad implicit conversion */
	if (val_is_ip4(&v1)) {
	  l->attrs[0].u.data = ipa_to_u32(v1.val.ip);
	  break;
	}
	/* T_INT for backward compatibility */
	if ((v1.type != T_QUAD) && (v1.type != T_INT))
	  runtime( "Setting quad attribute to non-quad value" );
	l->attrs[0].u.data = v1.val.i;
	break;

      case EAF_TYPE_OPAQUE:
	runtime( "Setting opaque attribute is not allowed" );
	break;
      case EAF_TYPE_IP_ADDRESS:
	if (v1.type != T_IP)
	  runtime( "Setting ip attribute to non-ip value" );
	int len = sizeof(ip_addr);
	struct adata *ad = lp_alloc(fs->pool, sizeof(struct adata) + len);
	ad->length = len;
	(* (ip_addr *) ad->data) = v1.val.ip;
	l->attrs[0].u.ptr = ad;
	break;
      case EAF_TYPE_AS_PATH:
	if (v1.type != T_PATH)
	  runtime( "Setting path attribute to non-path value" );
	l->attrs[0].u.ptr = v1.val.ad;
	break;
      case EAF_TYPE_BITFIELD:
	if (v1.type != T_BOOL)
	  runtime( "Setting bit in bitfield attribute to non-bool value" );
	{
	  /* First, we have to find the old value */
	  eattr *e = ea_find(*fs->eattrs, da.ea_code);
	  u32 data = e ? e->u.data : 0;

	  if (v1.val.i)
	    l->attrs[0].u.data = data | (1u << da.bit);
	  else
	    l->attrs[0].u.data = data & ~(1u << da.bit);
	}
	break;
      case EAF_TYPE_INT_SET:
	if (v1.type != T_CLIST)
	  runtime( "Setting clist attribute to non-clist value" );
	l->attrs[0].u.ptr = v1.val.ad;
	break;
      case EAF_TYPE_EC_SET:
	if (v1.type != T_ECLIST)
	  runtime( "Setting eclist attribute to non-eclist value" );
	l->attrs[0].u.ptr = v1.val.ad;
	break;
      case EAF_TYPE_LC_SET:
	if (v1.type != T_LCLIST)
	  runtime( "Setting lclist attribute to non-lclist value" );
	l->attrs[0].u.ptr = v1.val.ad;
	break;
      default: bug("Unknown type in e,S");
      }

      f_rta_cow(fs);
      l->next = *fs->eattrs;
      *fs->eattrs = l;
    }
  }

  INST(FI_EA_UNSET, 0, 0) {
    DYNAMIC_ATTR;
    ACCESS_RTE;
    ACCESS_EATTRS;

    {
      struct ea_list *l = lp_alloc(fs->pool, sizeof(struct ea_list) + sizeof(eattr));

      l->next = NULL;
      l->flags = EALF_SORTED;
      l->count = 1;
      l->attrs[0].id = da.ea_code;
      l->attrs[0].flags = 0;
      l->attrs[0].type = EAF_TYPE_UNDEF | EAF_TEMP | EAF_ORIGINATED | EAF_FRESH;
      l->attrs[0].u.data = 0;

      f_rta_cow(fs);
      l->next = *fs->eattrs;
      *fs->eattrs = l;
    }
  }

  INST(FI_PREF_GET, 0, 1) {
    ACCESS_RTE;
    RESULT(T_INT, i, (*fs->rte)->pref);
  }

  INST(FI_PREF_SET, 1, 0) {
    ACCESS_RTE;
    ARG(1,T_INT);
    if (v1.val.i > 0xFFFF)
      runtime( "Setting preference value out of bounds" );
    f_rte_cow(fs);
    (*fs->rte)->pref = v1.val.i;
  }

  INST(FI_LENGTH, 1, 1) {	/* Get length of */
    ARG_ANY(1);
    switch(v1.type) {
    case T_NET:    RESULT(T_INT, i, net_pxlen(v1.val.net)); break;
    case T_PATH:   RESULT(T_INT, i, as_path_getlen(v1.val.ad)); break;
    case T_CLIST:  RESULT(T_INT, i, int_set_get_size(v1.val.ad)); break;
    case T_ECLIST: RESULT(T_INT, i, ec_set_get_size(v1.val.ad)); break;
    case T_LCLIST: RESULT(T_INT, i, lc_set_get_size(v1.val.ad)); break;
    default: runtime( "Prefix, path, clist or eclist expected" );
    }
  }

  INST(FI_SADR_SRC, 1, 1) { 	/* Get SADR src prefix */
    ARG(1, T_NET);
    if (!net_is_sadr(v1.val.net))
      runtime( "SADR expected" );

    net_addr_ip6_sadr *net = (void *) v1.val.net;
    net_addr *src = lp_alloc(fs->pool, sizeof(net_addr_ip6));
    net_fill_ip6(src, net->src_prefix, net->src_pxlen);

    RESULT(T_NET, net, src);
  }

  INST(FI_ROA_MAXLEN, 1, 1) { 	/* Get ROA max prefix length */
    ARG(1, T_NET);
    if (!net_is_roa(v1.val.net))
      runtime( "ROA expected" );

    RESULT(T_INT, i, (v1.val.net->type == NET_ROA4) ?
      ((net_addr_roa4 *) v1.val.net)->max_pxlen :
      ((net_addr_roa6 *) v1.val.net)->max_pxlen);
  }

  INST(FI_ROA_ASN, 1, 1) { 	/* Get ROA ASN */
    ARG(1, T_NET);
    if (!net_is_roa(v1.val.net))
      runtime( "ROA expected" );

    RESULT(T_INT, i, (v1.val.net->type == NET_ROA4) ?
      ((net_addr_roa4 *) v1.val.net)->asn :
      ((net_addr_roa6 *) v1.val.net)->asn);
  }

  INST(FI_IP, 1, 1) {	/* Convert prefix to ... */
    ARG(1, T_NET);
    RESULT(T_IP, ip, net_prefix(v1.val.net));
  }

  INST(FI_ROUTE_DISTINGUISHER, 1, 1) {
    ARG(1, T_NET);
    if (!net_is_vpn(v1.val.net))
      runtime( "VPN address expected" );
    RESULT(T_RD, ec, net_rd(v1.val.net));
  }

  INST(FI_AS_PATH_FIRST, 1, 1) {	/* Get first ASN from AS PATH */
    ARG(1, T_PATH);
    int as = 0;
    as_path_get_first(v1.val.ad, &as);
    RESULT(T_INT, i, as);
  }

  INST(FI_AS_PATH_LAST, 1, 1) {	/* Get last ASN from AS PATH */
    ARG(1, T_PATH);
    int as = 0;
    as_path_get_last(v1.val.ad, &as);
    RESULT(T_INT, i, as);
  }

  INST(FI_AS_PATH_LAST_NAG, 1, 1) {	/* Get last ASN from non-aggregated part of AS PATH */
    ARG(1, T_PATH);
    RESULT(T_INT, i, as_path_get_last_nonaggregated(v1.val.ad));
  }

  INST(FI_RETURN, 1, 1) {
    /* Acquire the return value */
    ARG_ANY(1);
    uint retpos = vstk.cnt;

    /* Drop every sub-block including ourselves */
    while ((estk.cnt-- > 0) && !(estk.item[estk.cnt].emask & FE_RETURN))
      ;

    /* Now we are at the caller frame; if no such, try to convert to accept/reject. */
    if (!estk.cnt)
      if (vstk.val[retpos].type == T_BOOL)
	if (vstk.val[retpos].val.i)

	  return F_ACCEPT;
	else
	  return F_REJECT;
      else
	runtime("Can't return non-bool from non-function");

    /* Set the value stack position */
    vstk.cnt = estk.item[estk.cnt].ventry;

    /* Copy the return value */
    RESULT_VAL(vstk.val[retpos]);
  }

  INST(FI_CALL, 0, 1) {
    FID_LINE_IN
      const struct f_line *args;
      const struct f_line *body;
      struct symbol *sym;
    FID_STRUCT_IN
      struct symbol *sym;
      const struct f_inst *args;
    FID_NEW_ARGS
      , struct symbol * sym
      , const struct f_inst *args
    FID_NEW_BODY
      if (sym->class != SYM_FUNCTION)
	cf_error("You can't call something which is not a function. Really.");

      uint count = 0;
      for (const struct f_inst *inst = args; inst; inst = inst->next)
	count++;

      if (count != sym->function->args)
	cf_error("Function %s takes %u arguments, got %u.", sym->name, sym->function->args, count);

      what->sym = sym;
      what->args = args;
    FID_DUMP_BODY
      debug("%scalling %s with following args\n", INDENT, item->sym->name);
      f_dump_line(item->args, indent + 1);
    FID_POSTFIXIFY_BODY
      item->args = f_postfixify(what->args);
      item->body = (item->sym = what->sym)->function;
    FID_SAME_BODY
      /* To be done better */
      if (strcmp(f1->sym->name, f2->sym->name)) return 0;
      if (!f_same(f1->args, f2->args)) return 0;
      if (!f_same(f1->body, f2->body)) return 0;
    FID_ALL

    /* First push the body on stack */
    LINEX(whati->body);
    curline.emask |= FE_RETURN;

    /* Then push the arguments */
    LINEX(whati->args);
  }

  INST(FI_DROP_RESULT, 1, 0) {
    ARG_ANY(1);
  }

  INST(FI_SWITCH, 1, 0) {
    ARG_ANY(1);
    TREE;
    const struct f_tree *t = find_tree(tree, &v1);
    if (!t) {
      v1.type = T_VOID;
      t = find_tree(tree, &v1);
      if (!t) {
	debug( "No else statement?\n");
	break;
      }
    }
    /* It is actually possible to have t->data NULL */

    LINEX(t->data);
  }

  INST(FI_IP_MASK, 2, 1) { /* IP.MASK(val) */
    ARG(1, T_IP);
    ARG(2, T_INT);
    RESULT(T_IP, ip, [[ ipa_is_ip4(v1.val.ip) ?
      ipa_from_ip4(ip4_and(ipa_to_ip4(v1.val.ip), ip4_mkmask(v2.val.i))) :
      ipa_from_ip6(ip6_and(ipa_to_ip6(v1.val.ip), ip6_mkmask(v2.val.i))) ]]);
  }

  INST(FI_PATH_PREPEND, 2, 1) {	/* Path prepend */
    ARG(1, T_PATH);
    ARG(2, T_INT);
    RESULT(T_PATH, ad, [[ as_path_prepend(fs->pool, v1.val.ad, v2.val.i) ]]);
  }

  INST(FI_CLIST_ADD, 2, 1) {	/* (Extended) Community list add */
    ARG_ANY(1);
    ARG_ANY(2);
    if (v1.type == T_PATH)
      runtime("Can't add to path");

    else if (v1.type == T_CLIST)
    {
      /* Community (or cluster) list */
      struct f_val dummy;

      if ((v2.type == T_PAIR) || (v2.type == T_QUAD))
	RESULT(T_CLIST, ad, [[ int_set_add(fs->pool, v1.val.ad, v2.val.i) ]]);
      /* IP->Quad implicit conversion */
      else if (val_is_ip4(&v2))
	RESULT(T_CLIST, ad, [[ int_set_add(fs->pool, v1.val.ad, ipa_to_u32(v2.val.ip)) ]]);
      else if ((v2.type == T_SET) && clist_set_type(v2.val.t, &dummy))
	runtime("Can't add set");
      else if (v2.type == T_CLIST)
	RESULT(T_CLIST, ad, [[ int_set_union(fs->pool, v1.val.ad, v2.val.ad) ]]);
      else
	runtime("Can't add non-pair");
    }

    else if (v1.type == T_ECLIST)
    {
      /* v2.val is either EC or EC-set */
      if ((v2.type == T_SET) && eclist_set_type(v2.val.t))
	runtime("Can't add set");
      else if (v2.type == T_ECLIST)
	RESULT(T_ECLIST, ad, [[ ec_set_union(fs->pool, v1.val.ad, v2.val.ad) ]]);
      else if (v2.type != T_EC)
	runtime("Can't add non-ec");
      else
	RESULT(T_ECLIST, ad, [[ ec_set_add(fs->pool, v1.val.ad, v2.val.ec) ]]);
    }

    else if (v1.type == T_LCLIST)
    {
      /* v2.val is either LC or LC-set */
      if ((v2.type == T_SET) && lclist_set_type(v2.val.t))
	runtime("Can't add set");
      else if (v2.type == T_LCLIST)
	RESULT(T_LCLIST, ad, [[ lc_set_union(fs->pool, v1.val.ad, v2.val.ad) ]]);
      else if (v2.type != T_LC)
	runtime("Can't add non-lc");
      else
	RESULT(T_LCLIST, ad, [[ lc_set_add(fs->pool, v1.val.ad, v2.val.lc) ]]);

    }

    else
      runtime("Can't add to non-[e|l]clist");
  }

  INST(FI_CLIST_DEL, 2, 1) {	/* (Extended) Community list add or delete */
    ARG_ANY(1);
    ARG_ANY(2);
    if (v1.type == T_PATH)
    {
      const struct f_tree *set = NULL;
      u32 key = 0;

      if (v2.type == T_INT)
	key = v2.val.i;
      else if ((v2.type == T_SET) && (v2.val.t->from.type == T_INT))
	set = v2.val.t;
      else
	runtime("Can't delete non-integer (set)");

      RESULT(T_PATH, ad, [[ as_path_filter(fs->pool, v1.val.ad, set, key, 0) ]]);
    }

    else if (v1.type == T_CLIST)
    {
      /* Community (or cluster) list */
      struct f_val dummy;

      if ((v2.type == T_PAIR) || (v2.type == T_QUAD))
	RESULT(T_CLIST, ad, [[ int_set_del(fs->pool, v1.val.ad, v2.val.i) ]]);
      /* IP->Quad implicit conversion */
      else if (val_is_ip4(&v2))
	RESULT(T_CLIST, ad, [[ int_set_del(fs->pool, v1.val.ad, ipa_to_u32(v2.val.ip)) ]]);
      else if ((v2.type == T_SET) && clist_set_type(v2.val.t, &dummy) || (v2.type == T_CLIST))
	RESULT(T_CLIST, ad, [[ clist_filter(fs->pool, v1.val.ad, &v2, 0) ]]);
      else
	runtime("Can't delete non-pair");
    }

    else if (v1.type == T_ECLIST)
    {
      /* v2.val is either EC or EC-set */
      if ((v2.type == T_SET) && eclist_set_type(v2.val.t) || (v2.type == T_ECLIST))
	RESULT(T_ECLIST, ad, [[ eclist_filter(fs->pool, v1.val.ad, &v2, 0) ]]);
      else if (v2.type != T_EC)
	runtime("Can't delete non-ec");
      else
	RESULT(T_ECLIST, ad, [[ ec_set_del(fs->pool, v1.val.ad, v2.val.ec) ]]);
    }

    else if (v1.type == T_LCLIST)
    {
      /* v2.val is either LC or LC-set */
      if ((v2.type == T_SET) && lclist_set_type(v2.val.t) || (v2.type == T_LCLIST))
	RESULT(T_LCLIST, ad, [[ lclist_filter(fs->pool, v1.val.ad, &v2, 0) ]]);
      else if (v2.type != T_LC)
	runtime("Can't delete non-lc");
      else
	RESULT(T_LCLIST, ad, [[ lc_set_del(fs->pool, v1.val.ad, v2.val.lc) ]]);
    }

    else
      runtime("Can't delete in non-[e|l]clist");
  }

  INST(FI_CLIST_FILTER, 2, 1) {	/* (Extended) Community list add or delete */
    ARG_ANY(1);
    ARG_ANY(2);
    if (v1.type == T_PATH)
    {
      u32 key = 0;

      if ((v2.type == T_SET) && (v2.val.t->from.type == T_INT))
	RESULT(T_PATH, ad, [[ as_path_filter(fs->pool, v1.val.ad, v2.val.t, key, 1) ]]);
      else
	runtime("Can't filter integer");
    }

    else if (v1.type == T_CLIST)
    {
      /* Community (or cluster) list */
      struct f_val dummy;

      if ((v2.type == T_SET) && clist_set_type(v2.val.t, &dummy) || (v2.type == T_CLIST))
	RESULT(T_CLIST, ad, [[ clist_filter(fs->pool, v1.val.ad, &v2, 1) ]]);
      else
	runtime("Can't filter pair");
    }

    else if (v1.type == T_ECLIST)
    {
      /* v2.val is either EC or EC-set */
      if ((v2.type == T_SET) && eclist_set_type(v2.val.t) || (v2.type == T_ECLIST))
	RESULT(T_ECLIST, ad, [[ eclist_filter(fs->pool, v1.val.ad, &v2, 1) ]]);
      else
	runtime("Can't filter ec");
    }

    else if (v1.type == T_LCLIST)
    {
      /* v2.val is either LC or LC-set */
      if ((v2.type == T_SET) && lclist_set_type(v2.val.t) || (v2.type == T_LCLIST))
	RESULT(T_LCLIST, ad, [[ lclist_filter(fs->pool, v1.val.ad, &v2, 1) ]]);
      else
	runtime("Can't filter lc");
    }

    else
      runtime("Can't filter non-[e|l]clist");
  }

  INST(FI_ROA_CHECK_IMPLICIT, 0, 1) {	/* ROA Check */
    RTC(1);
    ACCESS_RTE;
    ACCESS_EATTRS;
    const net_addr *net = (*fs->rte)->net->n.addr;

    /* We ignore temporary attributes, probably not a problem here */
    /* 0x02 is a value of BA_AS_PATH, we don't want to include BGP headers */
    eattr *e = ea_find(*fs->eattrs, EA_CODE(PROTOCOL_BGP, 0x02));

    if (!e || ((e->type & EAF_TYPE_MASK) != EAF_TYPE_AS_PATH))
      runtime("Missing AS_PATH attribute");

    u32 as = 0;
    as_path_get_last(e->u.ptr, &as);

    if (!table)
      runtime("Missing ROA table");

    if (table->addr_type != NET_ROA4 && table->addr_type != NET_ROA6)
      runtime("Table type must be either ROA4 or ROA6");

    if (table->addr_type != (net->type == NET_IP4 ? NET_ROA4 : NET_ROA6))
      RESULT(T_ENUM_ROA, i, ROA_UNKNOWN); /* Prefix and table type mismatch */
    else
      RESULT(T_ENUM_ROA, i, [[ net_roa_check(table, net, as) ]]);
  }

  INST(FI_ROA_CHECK_EXPLICIT, 2, 1) {	/* ROA Check */
    ARG(1, T_NET);
    ARG(2, T_INT);
    RTC(3);

    u32 as = v2.val.i;

    if (!table)
      runtime("Missing ROA table");

    if (table->addr_type != NET_ROA4 && table->addr_type != NET_ROA6)
      runtime("Table type must be either ROA4 or ROA6");

    if (table->addr_type != (v1.val.net->type == NET_IP4 ? NET_ROA4 : NET_ROA6))
      RESULT(T_ENUM_ROA, i, ROA_UNKNOWN); /* Prefix and table type mismatch */
    else
      RESULT(T_ENUM_ROA, i, [[ net_roa_check(table, v1.val.net, as) ]]);

  }

  INST(FI_FORMAT, 1, 0) {	/* Format */
    ARG_ANY(1);
    RESULT(T_STRING, s, val_format_str(fs, &v1));
  }

  INST(FI_ASSERT, 1, 0) {	/* Birdtest Assert */
    ARG(1, T_BOOL);
    STRING;
    if (!bt_assert_hook)
      runtime("No bt_assert hook registered, can't assert");

    bt_assert_hook(res.val.i, what);
  }
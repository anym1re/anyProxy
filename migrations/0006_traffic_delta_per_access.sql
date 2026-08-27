-- One delivery carries a delta for every access the node serves, and the
-- revision names the delivery rather than the delta.
--
-- Remembering the revision alone meant the first delta claimed it and every
-- other delta in the same delivery was taken for a repeat and dropped. A node
-- serving one access counted correctly; a node serving three counted a third
-- of what it carried, quietly, and no quota it fed was ever right.

alter table traffic_delta drop constraint traffic_delta_pkey;
alter table traffic_delta add primary key (revision, access_id, day);

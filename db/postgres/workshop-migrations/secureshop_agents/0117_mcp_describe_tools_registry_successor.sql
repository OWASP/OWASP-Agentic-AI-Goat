-- Forward-only v38 administrator MCP description-read ACL successor.
-- Historical edges and instructor overrides remain immutable; a populated
-- policy receives an explicit denial for the newly supported read permission.
DO $$
DECLARE
 guard_source text; v37_case text; v38_case text; constraint_def text; denial_constraint_def text;
 old_guard_sha256 constant text := '851ca7a3b08b91dcc124112a2fe2cb01daf9f8c497e8dc445ef077571893ab4e';
 upgraded_guard_sha256 constant text := '36f1ed75cc90c0e62c30a5495bcea4ddbbd024f3fd184391f33dfd606e7ce9af';
 old_edge constant text := $value$   OR (encode(NEW.predecessor_sha256,'hex')='48ac68d48fdf589a234b07dd6f80b1b70d399d4bcfed65d55e2647255750fe56' AND encode(NEW.successor_sha256,'hex')='e9958aeb38ccc1e59115c316961a27345a55886c657b9989565d3bd1e1024697')$value$;
 new_edges constant text := $value$   OR (encode(NEW.predecessor_sha256,'hex')='e01641f40076b2de5a3b250ef5e62156ae9fca0752c467cfeee5e9ff846f8c83' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='94a618b7985f5d674d04e660e98fb65704b798d82d5ba212e24198a5895bd0a0' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='4fcf0a5032fac72ff4e907909e431403fc1fa8caccf673f4937855143adb479b' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='45c1d52e58c9db3e4eaefa28cb472e2d5f9b555c4b94721923a1f851b4016626' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='b304723f3db4faa9f94014e5231ad3b99289083732e0a892081187a44ead77dd' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='9e427b77e3c4957eef0a7d82fe66fb5ddca17c5192ae0551b89bbce67ef114ba' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='7033c43968337d22aa51a32d7b59c8560cb5b7bff684f77880fa3ed4d5c97e70' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='11d22a92e0860da587c40c7c4b0624f30f090217283104ef8b4eecf1f624a7b3' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='45523b86483491e9ad584814f3feb2296a33fd1eef3d1dee9649726e6e6bf04b' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='fa2ca449a16bb4cf176f298934022c3bb62ad47853d8ff53af81b82a0b2da9ea' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='69598fe7cd484a95fe46fb856f1240499a1381a84ba289178262d6dd86d41e96' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='ea01e56229188d248e9513097b5551c2d8eb7363c8790dad66b618a781ec79d8' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='45893991ebda645902f9af8d0c55dde316ce67715fec4d19ebfc63db99f3aa19' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='34005b3480e2dfe11e49221f812fcdd62e7d1851880d2c87bda09f4791f335ae' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='a927f19c9101ea9ced754fe0609cddde7885169763986d004f14a55695247b01' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='1744f9c32cc93cf6708d6512288313c833fce84ca5496515f6155c50d1a39fff' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='2df507e918c1ecba5d8ebac3a0d0ba63e88909c70f0b37d8c198082cc1baad7d' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='5aa6284201a2d234efd7dbe2d2d31599e1e167f410d23aa8b2890f48c561ee9b' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='1678d1c76c1e5565c6d09e62dc9e80e3d5d7bb3bfb0fa7a405b1f0579f586c72' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='0a9e93f87983045aa3194f2794f63118a3d62979d3dada88eb91e2e22ff4c15c' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='7b61d5cd1f2dcb98585b0a4312423df33b2a2d2df54905bf394a6e6717719beb' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='974d64bf78037ad3de2dbba5a28f277feab87487c13477b8b81b6c11540c8ea1' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='cd81b73f42c6de9c1bd9d975606ee29e05f53ff77212ffba68542d305626dcda' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='48ac68d48fdf589a234b07dd6f80b1b70d399d4bcfed65d55e2647255750fe56' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')
   OR (encode(NEW.predecessor_sha256,'hex')='e9958aeb38ccc1e59115c316961a27345a55886c657b9989565d3bd1e1024697' AND encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59')$value$;
 old_anchor constant text := $value$ IF encode(NEW.successor_sha256,'hex')='e9958aeb38ccc1e59115c316961a27345a55886c657b9989565d3bd1e1024697' THEN$value$;
 new_anchor constant text := $value$ IF encode(NEW.successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' THEN$value$;
 old_prefix constant text := $value$  expected_denials=CASE encode(NEW.predecessor_sha256,'hex')$value$;
 new_prefix constant text := $value$  expected_denials=(SELECT jsonb_agg(value ORDER BY (value->>'toolKey') COLLATE "C",(value->>'role') COLLATE "C") FROM jsonb_array_elements((CASE encode(NEW.predecessor_sha256,'hex')$value$;
 new_suffix constant text := $value$  WHEN 'e9958aeb38ccc1e59115c316961a27345a55886c657b9989565d3bd1e1024697' THEN '[]'::jsonb
 ELSE NULL END) || '[{"toolKey":"mcp-registry.describe_tools","role":"admin"}]'::jsonb) value);$value$;
 denial_anchor constant text := $anchor$
 SELECT jsonb_agg(value ORDER BY (value->>'toolKey') COLLATE "C",(value->>'role') COLLATE "C") INTO expected_denials$anchor$;
 constraint_additions constant text := $value$
  OR (encode(predecessor_sha256,'hex')='e01641f40076b2de5a3b250ef5e62156ae9fca0752c467cfeee5e9ff846f8c83' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=25)
  OR (encode(predecessor_sha256,'hex')='94a618b7985f5d674d04e660e98fb65704b798d82d5ba212e24198a5895bd0a0' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=31)
  OR (encode(predecessor_sha256,'hex')='4fcf0a5032fac72ff4e907909e431403fc1fa8caccf673f4937855143adb479b' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=34)
  OR (encode(predecessor_sha256,'hex')='45c1d52e58c9db3e4eaefa28cb472e2d5f9b555c4b94721923a1f851b4016626' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=40)
  OR (encode(predecessor_sha256,'hex')='b304723f3db4faa9f94014e5231ad3b99289083732e0a892081187a44ead77dd' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=46)
  OR (encode(predecessor_sha256,'hex')='9e427b77e3c4957eef0a7d82fe66fb5ddca17c5192ae0551b89bbce67ef114ba' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=47)
  OR (encode(predecessor_sha256,'hex')='7033c43968337d22aa51a32d7b59c8560cb5b7bff684f77880fa3ed4d5c97e70' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=49)
  OR (encode(predecessor_sha256,'hex')='11d22a92e0860da587c40c7c4b0624f30f090217283104ef8b4eecf1f624a7b3' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=51)
  OR (encode(predecessor_sha256,'hex')='45523b86483491e9ad584814f3feb2296a33fd1eef3d1dee9649726e6e6bf04b' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=54)
  OR (encode(predecessor_sha256,'hex')='a6c95973a6aac45a487424e291340f0bb17f5a32e1e762ce116bf11579916e64' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=79)
  OR (encode(predecessor_sha256,'hex')='93c0ccf3965c434b2cdf6e5b980d11b6472d3c43f87d04a29409de1e24c37eed' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=64)
  OR (encode(predecessor_sha256,'hex')='a18e40fda6882f7bff2f3c71887362b45db5414e53296794198a0923ca2bb427' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=63)
  OR (encode(predecessor_sha256,'hex')='640083068bae4a7ef8a268016af19e991d04c09364366526eafdc54f28e3a9e1' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=61)
  OR (encode(predecessor_sha256,'hex')='4b2b1ce7ac7fe84db081f103fd200d083d81ee720f38c9c6c3ecd6c9f8524e26' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=60)
  OR (encode(predecessor_sha256,'hex')='f9d81c85cc3a29885526d336c78b82ec886fcf3bae8778c0222a2806400a590b' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=59)
  OR (encode(predecessor_sha256,'hex')='2abbb63e6c470cdff613927ba1519ef0156f2016c88d97abe7918a058be1d4f0' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=58)
  OR (encode(predecessor_sha256,'hex')='fa2ca449a16bb4cf176f298934022c3bb62ad47853d8ff53af81b82a0b2da9ea' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=56)
  OR (encode(predecessor_sha256,'hex')='69598fe7cd484a95fe46fb856f1240499a1381a84ba289178262d6dd86d41e96' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=57)
  OR (encode(predecessor_sha256,'hex')='ac2df913bae81b4ca258cc6b30f6b62ecee9b975b37d30a13b14e2963b393daf' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=24)
  OR (encode(predecessor_sha256,'hex')='ea01e56229188d248e9513097b5551c2d8eb7363c8790dad66b618a781ec79d8' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=23)
  OR (encode(predecessor_sha256,'hex')='45893991ebda645902f9af8d0c55dde316ce67715fec4d19ebfc63db99f3aa19' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=20)
  OR (encode(predecessor_sha256,'hex')='34005b3480e2dfe11e49221f812fcdd62e7d1851880d2c87bda09f4791f335ae' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=18)
  OR (encode(predecessor_sha256,'hex')='a927f19c9101ea9ced754fe0609cddde7885169763986d004f14a55695247b01' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=16)
  OR (encode(predecessor_sha256,'hex')='1744f9c32cc93cf6708d6512288313c833fce84ca5496515f6155c50d1a39fff' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=15)
  OR (encode(predecessor_sha256,'hex')='2df507e918c1ecba5d8ebac3a0d0ba63e88909c70f0b37d8c198082cc1baad7d' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=14)
  OR (encode(predecessor_sha256,'hex')='5aa6284201a2d234efd7dbe2d2d31599e1e167f410d23aa8b2890f48c561ee9b' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=13)
  OR (encode(predecessor_sha256,'hex')='f2e090620c962d94d19048d03668145ddace7a9fb77bc2588e3add3eed910e0c' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=12)
  OR (encode(predecessor_sha256,'hex')='1678d1c76c1e5565c6d09e62dc9e80e3d5d7bb3bfb0fa7a405b1f0579f586c72' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=11)
  OR (encode(predecessor_sha256,'hex')='bc8edf04a8a13b42871d01699c19c0782d6093fc190df49c999a8d877228fd71' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=10)
  OR (encode(predecessor_sha256,'hex')='e747a55517a50d484901bcc78a98747c98773042cb2bff6396a7654722a470ef' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=9)
  OR (encode(predecessor_sha256,'hex')='0a9e93f87983045aa3194f2794f63118a3d62979d3dada88eb91e2e22ff4c15c' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=8)
  OR (encode(predecessor_sha256,'hex')='7b61d5cd1f2dcb98585b0a4312423df33b2a2d2df54905bf394a6e6717719beb' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=6)
  OR (encode(predecessor_sha256,'hex')='435e367f41c95102c5d9fedc80974c8761250878c6755fb2a7e454a159d126bc' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=5)
  OR (encode(predecessor_sha256,'hex')='974d64bf78037ad3de2dbba5a28f277feab87487c13477b8b81b6c11540c8ea1' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=4)
  OR (encode(predecessor_sha256,'hex')='cd81b73f42c6de9c1bd9d975606ee29e05f53ff77212ffba68542d305626dcda' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=3)
  OR (encode(predecessor_sha256,'hex')='48ac68d48fdf589a234b07dd6f80b1b70d399d4bcfed65d55e2647255750fe56' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=2)
  OR (encode(predecessor_sha256,'hex')='e9958aeb38ccc1e59115c316961a27345a55886c657b9989565d3bd1e1024697' AND encode(successor_sha256,'hex')='94323e2d08fa271b3b523e1da95cd0e87fded5a63732f1ca9506111e9ed27c59' AND jsonb_array_length(added_denials)=1)$value$;
BEGIN
 SELECT prosrc INTO guard_source FROM pg_proc
  WHERE oid='secureshop_agents.guard_bound_tool_registry_upgrade()'::regprocedure;
 IF guard_source IS NULL
  OR encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>old_guard_sha256
  OR strpos(guard_source,old_edge)=0
  OR array_length(string_to_array(guard_source,old_edge),1)<>2
  OR strpos(guard_source,old_anchor)=0
  OR array_length(string_to_array(guard_source,old_anchor),1)<>2
  OR array_length(string_to_array(guard_source,denial_anchor),1)<>2
  OR strpos(split_part(guard_source,old_anchor,2),E' ELSE NULL END;')=0 THEN
  RAISE EXCEPTION 'Expected v37 registry guard unavailable' USING ERRCODE='55000';
 END IF;
 v37_case:=old_anchor||split_part(split_part(guard_source,old_anchor,2),E' ELSE NULL END;',1)||E' ELSE NULL END;';
 IF strpos(v37_case,old_prefix)=0 OR array_length(string_to_array(v37_case,old_prefix),1)<>2 THEN
  RAISE EXCEPTION 'Expected v37 canonical denial branch unavailable' USING ERRCODE='55000';
 END IF;
 v38_case:=replace(v37_case,old_anchor,new_anchor);
 v38_case:=replace(v38_case,old_prefix,new_prefix);
 v38_case:=replace(v38_case,E' ELSE NULL END;',new_suffix);
 guard_source:=replace(guard_source,old_edge,old_edge||E'\n'||new_edges);
 guard_source:=replace(guard_source,old_anchor,v38_case||E'\n ELSE\n'||old_anchor);
 guard_source:=replace(guard_source,denial_anchor,E'\n END IF;'||denial_anchor);
 IF encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>upgraded_guard_sha256 THEN
  RAISE EXCEPTION 'Description registry guard checksum mismatch' USING ERRCODE='55000';
 END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS %L',guard_source);
 SELECT pg_get_constraintdef(c.oid) INTO constraint_def FROM pg_constraint c
  WHERE c.conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
   AND c.conname='bound_tool_registry_successor_v37' AND c.contype='c' AND c.convalidated;
 IF constraint_def IS NULL
  OR position('e9958aeb38ccc1e59115c316961a27345a55886c657b9989565d3bd1e1024697' IN constraint_def)=0 THEN
  RAISE EXCEPTION 'Expected v37 registry successor unavailable' USING ERRCODE='55000';
 END IF;
 SELECT pg_get_constraintdef(c.oid) INTO denial_constraint_def FROM pg_constraint c
  WHERE c.conrelid='secureshop_agents.bound_tool_registry_upgrades'::regclass
   AND c.conname='bound_tool_registry_upgrades_added_denials_check' AND c.contype='c' AND c.convalidated;
 IF denial_constraint_def IS NULL OR position('78' IN denial_constraint_def)=0 THEN
  RAISE EXCEPTION 'Expected v37 denial cardinalities unavailable' USING ERRCODE='55000';
 END IF;
 ALTER TABLE secureshop_agents.bound_tool_registry_upgrades
  DROP CONSTRAINT bound_tool_registry_upgrades_added_denials_check,
  ADD CONSTRAINT bound_tool_registry_upgrades_added_denials_check
   CHECK(jsonb_typeof(added_denials)='array' AND jsonb_array_length(added_denials) IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,69,70,71,73,74,75,76,77,78,79));
 constraint_def:=regexp_replace(constraint_def,E'\\)\\s*$' ,constraint_additions||E'\n)');
 EXECUTE 'ALTER TABLE secureshop_agents.bound_tool_registry_upgrades ADD CONSTRAINT bound_tool_registry_successor_v38 '||constraint_def;
 ALTER TABLE secureshop_agents.bound_tool_registry_upgrades DROP CONSTRAINT bound_tool_registry_successor_v37;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade() FROM PUBLIC,dvaia_secureshop_agents_runtime;


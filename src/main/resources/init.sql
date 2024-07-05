-- ----------------------------
-- SEQUENCE structure for "public"."batch_step_execution_seq"
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."batch_step_execution_seq";
CREATE SEQUENCE "public"."batch_step_execution_seq"
INCREMENT 1
MINVALUE 1
MAXVALUE 9223372036854775807
START 1;-- ----------------------------
-- SEQUENCE structure for "public"."batch_job_execution_seq"
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."batch_job_execution_seq";
CREATE SEQUENCE "public"."batch_job_execution_seq"
INCREMENT 1
MINVALUE 1
MAXVALUE 9223372036854775807
START 1;-- ----------------------------
-- SEQUENCE structure for "public"."batch_job_seq"
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."batch_job_seq";
CREATE SEQUENCE "public"."batch_job_seq"
INCREMENT 1
MINVALUE 1
MAXVALUE 9223372036854775807
START 1;

-- ----------------------------
-- Table structure for public.package_statistics
-- ----------------------------
CREATE TABLE "public"."package_statistics"(
	"id" uuid NOT NULL,
	"critical_vul_count" int8 NULL,
	"dep_count" int8 NULL,
	"high_vul_count" int8 NULL,
	"is_legal_license" bool NULL,
	"license_count" int8 NULL,
	"licenses" _text NULL,
	"low_vul_count" int8 NULL,
	"medium_vul_count" int8 NULL,
	"module_count" int8 NULL,
	"none_vul_count" int8 NULL,
	"runtime_dep_count" int8 NULL,
	"severity" text NULL,
	"unknown_vul_count" int8 NULL,
	"vul_count" int8 NULL,
	"package_id" uuid NOT NULL,
	CONSTRAINT "package_statistics_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17564_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17564_16_not_null" CHECK (package_id IS NOT NULL),
	CONSTRAINT "product_id_fk" FOREIGN KEY (product_id,package_id) REFERENCES "public"."product" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX uk_h9tkg5njnrjgca53nw5i926wf ON public.package_statistics USING btree (package_id);

CREATE TABLE "public"."raw_sbom"(
	"id" uuid NOT NULL,
	"create_time" timestamptz NULL,
	"job_execution_id" int8 NULL,
	"task_id" uuid NULL,
	"task_status" text NULL,
	"update_time" timestamptz NULL,
	"value" bytea NOT NULL,
	"product_id" uuid NOT NULL,
	"value_type" text NOT NULL,
	CONSTRAINT "raw_sbom_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_16516_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_16516_10_not_null" CHECK (value IS NOT NULL),
	CONSTRAINT "2200_16516_11_not_null" CHECK (product_id IS NOT NULL),
	CONSTRAINT "2200_16516_12_not_null" CHECK (value_type IS NOT NULL),
	CONSTRAINT "product_id_fk" FOREIGN KEY (product_id,package_id) REFERENCES "public"."product" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX raw_sbom_uk ON public.raw_sbom USING btree (value_type, product_id);

CREATE TABLE "public"."package_meta"(
	"checksum" text NOT NULL,
	"checksum_type" text NOT NULL,
	"extended_attr" jsonb NULL,
	"purl" jsonb NULL,
	CONSTRAINT "package_meta_pkey" PRIMARY KEY ("checksum"),
	CONSTRAINT "2200_26953_1_not_null" CHECK (checksum IS NOT NULL),
	CONSTRAINT "2200_26953_2_not_null" CHECK (checksum_type IS NOT NULL)
);

CREATE TABLE "public"."pkg_license_relp"(
	"pkg_id" uuid NULL,
	"license_id" uuid NULL,
	"id" uuid NOT NULL,
	CONSTRAINT "pkg_license_relp_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17025_3_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "pkg_id_fk" FOREIGN KEY (pkg_id) REFERENCES "public"."package" (id),
	CONSTRAINT "license_id_fk" FOREIGN KEY (license_id) REFERENCES "public"."license" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX pkg_license_uk ON public.pkg_license_relp USING btree (pkg_id, license_id);

CREATE TABLE "public"."repo_meta"(
	"id" uuid NOT NULL,
	"branch" text NULL,
	"download_location" varchar(255) NULL,
	"package_names" _text NULL,
	"patch_info" _text NULL,
	"product_type" text NULL,
	"repo_name" text NULL,
	"spec_download_url" varchar(255) NULL,
	"upstream_download_urls" _text NULL,
	"extended_attr" jsonb NULL,
	CONSTRAINT "repo_meta_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_16524_1_not_null" CHECK (id IS NOT NULL)
);

set search_path to "public";
CREATE UNIQUE INDEX repo_name_uk ON public.repo_meta USING btree (product_type, repo_name, branch);

CREATE TABLE "public"."product_config_value"(
	"id" uuid NOT NULL,
	"label" text NULL,
	"value" text NOT NULL,
	"product_config_id" uuid NOT NULL,
	CONSTRAINT "product_config_value_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_26961_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_26961_3_not_null" CHECK (value IS NOT NULL),
	CONSTRAINT "2200_26961_4_not_null" CHECK (product_config_id IS NOT NULL),
	CONSTRAINT "product_config_fk" FOREIGN KEY (product_config_id) REFERENCES "public"."product_config" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX config_value_uk ON public.product_config_value USING btree (product_config_id, value);

set search_path to "public";
CREATE UNIQUE INDEX config_label_uk ON public.product_config_value USING btree (product_config_id, label);

CREATE TABLE "public"."vul_reference"(
	"id" uuid NOT NULL,
	"url" text NULL,
	"vul_id" uuid NOT NULL,
	"type" text NULL,
	CONSTRAINT "vul_reference_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17110_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17110_4_not_null" CHECK (vul_id IS NOT NULL),
	CONSTRAINT "vul_id_fk" FOREIGN KEY (vul_id) REFERENCES "public"."vulnerability" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX vul_ref_uk ON public.vul_reference USING btree (type, url, vul_id);


CREATE TABLE "public"."batch_job_execution_params"(
	"job_execution_id" int8 NOT NULL,
	"type_cd" varchar(6) NOT NULL,
	"key_name" varchar(100) NOT NULL,
	"string_val" varchar(250) NULL,
	"date_val" timestamp NULL,
	"long_val" int8 NULL,
	"double_val" float8 NULL,
	"identifying" bpchar(1) NOT NULL,
	CONSTRAINT "2200_16726_1_not_null" CHECK (job_execution_id IS NOT NULL),
	CONSTRAINT "2200_16726_2_not_null" CHECK (type_cd IS NOT NULL),
	CONSTRAINT "2200_16726_3_not_null" CHECK (key_name IS NOT NULL),
	CONSTRAINT "2200_16726_8_not_null" CHECK (identifying IS NOT NULL),
	CONSTRAINT "job_exec_params_fk" FOREIGN KEY (job_execution_id) REFERENCES "public"."batch_job_execution" (job_execution_id)
);

CREATE TABLE "public"."batch_job_execution_context"(
	"job_execution_id" int8 NOT NULL,
	"short_context" varchar(2500) NOT NULL,
	"serialized_context" text NULL,
	CONSTRAINT "batch_job_execution_context_pkey" PRIMARY KEY ("job_execution_id"),
	CONSTRAINT "2200_16760_1_not_null" CHECK (job_execution_id IS NOT NULL),
	CONSTRAINT "2200_16760_2_not_null" CHECK (short_context IS NOT NULL),
	CONSTRAINT "job_exec_ctx_fk" FOREIGN KEY (job_execution_id) REFERENCES "public"."batch_job_execution" (job_execution_id)
);

CREATE TABLE "public"."batch_step_execution"(
	"step_execution_id" int8 NOT NULL,
	"version" int8 NOT NULL,
	"step_name" varchar(100) NOT NULL,
	"job_execution_id" int8 NOT NULL,
	"start_time" timestamp NOT NULL,
	"end_time" timestamp NULL,
	"status" varchar(10) NULL,
	"commit_count" int8 NULL,
	"read_count" int8 NULL,
	"filter_count" int8 NULL,
	"write_count" int8 NULL,
	"read_skip_count" int8 NULL,
	"write_skip_count" int8 NULL,
	"process_skip_count" int8 NULL,
	"rollback_count" int8 NULL,
	"exit_code" varchar(2500) NULL,
	"exit_message" varchar(2500) NULL,
	"last_updated" timestamp NULL,
	CONSTRAINT "batch_step_execution_pkey" PRIMARY KEY ("step_execution_id"),
	CONSTRAINT "2200_16734_1_not_null" CHECK (step_execution_id IS NOT NULL),
	CONSTRAINT "2200_16734_2_not_null" CHECK (version IS NOT NULL),
	CONSTRAINT "2200_16734_3_not_null" CHECK (step_name IS NOT NULL),
	CONSTRAINT "2200_16734_4_not_null" CHECK (job_execution_id IS NOT NULL),
	CONSTRAINT "2200_16734_5_not_null" CHECK (start_time IS NOT NULL),
	CONSTRAINT "job_exec_step_fk" FOREIGN KEY (job_execution_id) REFERENCES "public"."batch_job_execution" (job_execution_id)
);

CREATE TABLE "public"."external_purl_ref"(
	"id" uuid NOT NULL,
	"category" text NOT NULL,
	"comment" text NULL,
	"purl" jsonb NOT NULL,
	"type" text NOT NULL,
	"pkg_id" uuid NOT NULL,
	CONSTRAINT "external_purl_ref_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_16993_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_16993_2_not_null" CHECK (category IS NOT NULL),
	CONSTRAINT "2200_16993_4_not_null" CHECK (purl IS NOT NULL),
	CONSTRAINT "2200_16993_5_not_null" CHECK (type IS NOT NULL),
	CONSTRAINT "2200_16993_6_not_null" CHECK (pkg_id IS NOT NULL),
	CONSTRAINT "pkg_id_fk" FOREIGN KEY (pkg_id) REFERENCES "public"."package" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX external_purl_ref_uk ON public.external_purl_ref USING btree (pkg_id, category, type, purl);

set search_path to "public";
CREATE INDEX external_purl_ref_pkg_id_idx ON public.external_purl_ref USING btree (pkg_id);

set search_path to "public";
CREATE INDEX external_purl_ref_purl_idx ON public.external_purl_ref USING btree (jsonb_extract_path_text(purl, VARIADIC ARRAY['type'::text]), jsonb_extract_path_text(purl, VARIADIC ARRAY['name'::text]));

CREATE TABLE "public"."checksum"(
	"id" uuid NOT NULL,
	"algorithm" text NOT NULL,
	"value" text NOT NULL,
	"pkg_id" uuid NOT NULL,
	CONSTRAINT "checksum_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_16985_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_16985_2_not_null" CHECK (algorithm IS NOT NULL),
	CONSTRAINT "2200_16985_3_not_null" CHECK (value IS NOT NULL),
	CONSTRAINT "2200_16985_4_not_null" CHECK (pkg_id IS NOT NULL),
	CONSTRAINT "pkg_id_fk" FOREIGN KEY (pkg_id) REFERENCES "public"."package" (id)
);

set search_path to "public";
CREATE INDEX pkg_id_idx ON public.checksum USING btree (pkg_id);

set search_path to "public";
CREATE UNIQUE INDEX checksum_uk ON public.checksum USING btree (pkg_id, algorithm, value);

CREATE TABLE "public"."sbom"(
	"id" uuid NOT NULL,
	"created" text NULL,
	"data_license" text NULL,
	"license_list_version" text NULL,
	"name" text NULL,
	"namespace" text NULL,
	"product_id" uuid NOT NULL,
	CONSTRAINT "sbom_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17078_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17078_7_not_null" CHECK (product_id IS NOT NULL),
	CONSTRAINT "product_id_fk" FOREIGN KEY (product_id,package_id) REFERENCES "public"."product" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX product_id_uk ON public.sbom USING btree (product_id);

CREATE TABLE "public"."pkg_verf_code"(
	"id" uuid NOT NULL,
	"value" text NOT NULL,
	"pkg_id" uuid NOT NULL,
	CONSTRAINT "pkg_verf_code_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17030_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17030_2_not_null" CHECK (value IS NOT NULL),
	CONSTRAINT "2200_17030_3_not_null" CHECK (pkg_id IS NOT NULL),
	CONSTRAINT "pkg_id_fk" FOREIGN KEY (pkg_id) REFERENCES "public"."package" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX pkg_id_uk ON public.pkg_verf_code USING btree (pkg_id);

CREATE TABLE "public"."external_vul_ref"(
	"id" uuid NOT NULL,
	"category" text NOT NULL,
	"comment" text NULL,
	"purl" jsonb NULL,
	"pkg_id" uuid NOT NULL,
	"vul_id" uuid NOT NULL,
	CONSTRAINT "external_vul_ref_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17001_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17001_2_not_null" CHECK (category IS NOT NULL),
	CONSTRAINT "2200_17001_7_not_null" CHECK (pkg_id IS NOT NULL),
	CONSTRAINT "2200_17001_8_not_null" CHECK (vul_id IS NOT NULL),
	CONSTRAINT "pkg_id_fk" FOREIGN KEY (pkg_id) REFERENCES "public"."package" (id),
	CONSTRAINT "vul_id_fk" FOREIGN KEY (vul_id) REFERENCES "public"."vulnerability" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX package_vul_purl_uk ON public.external_vul_ref USING btree (pkg_id, vul_id, purl);

CREATE TABLE "public"."pkg_verf_code_excluded_file"(
	"id" uuid NOT NULL,
	"file" text NOT NULL,
	"pkg_verf_code_id" uuid NOT NULL,
	CONSTRAINT "pkg_verf_code_excluded_file_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17038_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17038_2_not_null" CHECK (file IS NOT NULL),
	CONSTRAINT "2200_17038_3_not_null" CHECK (pkg_verf_code_id IS NOT NULL),
	CONSTRAINT "pkg_verf_code_id_fk" FOREIGN KEY (pkg_verf_code_id) REFERENCES "public"."pkg_verf_code" (id)
);

set search_path to "public";
CREATE INDEX pkg_verf_code_id_idx ON public.pkg_verf_code_excluded_file USING btree (pkg_verf_code_id);

set search_path to "public";
CREATE UNIQUE INDEX pkg_verf_code_file_uk ON public.pkg_verf_code_excluded_file USING btree (pkg_verf_code_id, file);

CREATE TABLE "public"."package"(
	"id" uuid NOT NULL,
	"copyright" text NULL,
	"description" text NULL,
	"download_location" text NULL,
	"files_analyzed" bool NULL,
	"homepage" text NULL,
	"license_concluded" text NULL,
	"license_declared" text NULL,
	"name" text NOT NULL,
	"source_info" text NULL,
	"spdx_id" text NULL,
	"summary" text NULL,
	"supplier" text NULL,
	"version" text NULL,
	"sbom_id" uuid NOT NULL,
	"originator" text NULL,
	CONSTRAINT "package_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17017_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17017_9_not_null" CHECK (name IS NOT NULL),
	CONSTRAINT "2200_17017_15_not_null" CHECK (sbom_id IS NOT NULL),
	CONSTRAINT "sbom_id_fk" FOREIGN KEY (sbom_id) REFERENCES "public"."sbom" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX package_uk ON public.package USING btree (sbom_id, spdx_id, name, version);

set search_path to "public";
CREATE INDEX package_name_idx ON public.package USING btree (sbom_id, name);

CREATE TABLE "public"."product"(
	"id" uuid NOT NULL,
	"attribute" jsonb NOT NULL,
	"name" text NOT NULL,
	"create_time" timestamptz NULL,
	CONSTRAINT "product_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17046_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17046_2_not_null" CHECK (attribute IS NOT NULL),
	CONSTRAINT "2200_17046_3_not_null" CHECK (name IS NOT NULL)
);

set search_path to "public";
CREATE UNIQUE INDEX name_uk ON public.product USING btree (name);

set search_path to "public";
CREATE UNIQUE INDEX attr_uk ON public.product USING btree (attribute);

CREATE TABLE "public"."product_statistics"(
	"id" uuid NOT NULL,
	"create_time" timestamptz NULL,
	"critical_vul_count" int8 NULL,
	"dep_count" int8 NULL,
	"high_vul_count" int8 NULL,
	"license_count" int8 NULL,
	"license_distribution" jsonb NULL,
	"low_vul_count" int8 NULL,
	"medium_vul_count" int8 NULL,
	"module_count" int8 NULL,
	"none_vul_count" int8 NULL,
	"package_count" int8 NULL,
	"package_with_critical_vul_count" int8 NULL,
	"package_with_high_vul_count" int8 NULL,
	"package_with_illegal_license_count" int8 NULL,
	"package_with_legal_license_count" int8 NULL,
	"package_with_low_vul_count" int8 NULL,
	"package_with_medium_vul_count" int8 NULL,
	"package_with_multi_license_count" int8 NULL,
	"package_with_none_vul_count" int8 NULL,
	"package_with_unknown_vul_count" int8 NULL,
	"package_without_license_count" int8 NULL,
	"package_without_vul_count" int8 NULL,
	"runtime_dep_count" int8 NULL,
	"unknown_vul_count" int8 NULL,
	"vul_count" int8 NULL,
	"product_id" uuid NOT NULL,
	CONSTRAINT "product_statistics_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17062_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17062_27_not_null" CHECK (product_id IS NOT NULL),
	CONSTRAINT "product_id_fk" FOREIGN KEY (product_id,package_id) REFERENCES "public"."product" (id)
);

CREATE TABLE "public"."license"(
	"id" uuid NOT NULL,
	"is_legal" bool NULL,
	"name" text NULL,
	"spdx_license_id" text NOT NULL,
	"url" text NULL,
	CONSTRAINT "license_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17009_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17009_4_not_null" CHECK (spdx_license_id IS NOT NULL)
);

set search_path to "public";
CREATE UNIQUE INDEX spdx_license_id_uk ON public.license USING btree (spdx_license_id);

CREATE TABLE "public"."product_type"(
	"type" text NOT NULL,
	"active" bool NULL,
	CONSTRAINT "product_type_pkey" PRIMARY KEY ("type"),
	CONSTRAINT "2200_17070_1_not_null" CHECK (type IS NOT NULL)
);

CREATE TABLE "public"."product_config"(
	"id" uuid NOT NULL,
	"label" text NOT NULL,
	"name" text NOT NULL,
	"ord" int4 NOT NULL,
	"product_type" text NOT NULL,
	CONSTRAINT "product_config_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17054_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17054_2_not_null" CHECK (label IS NOT NULL),
	CONSTRAINT "2200_17054_3_not_null" CHECK (name IS NOT NULL),
	CONSTRAINT "2200_17054_4_not_null" CHECK (ord IS NOT NULL),
	CONSTRAINT "2200_17054_6_not_null" CHECK (product_type IS NOT NULL),
	CONSTRAINT "product_type_fk" FOREIGN KEY (product_type) REFERENCES "public"."product_type" (type)
);

set search_path to "public";
CREATE INDEX product_type_idx ON public.product_config USING btree (product_type);

set search_path to "public";
CREATE UNIQUE INDEX name_product_type_uk ON public.product_config USING btree (name, product_type);

CREATE TABLE "public"."vul_score"(
	"id" uuid NOT NULL,
	"score" float8 NOT NULL,
	"scoring_system" text NOT NULL,
	"severity" text NOT NULL,
	"vector" text NOT NULL,
	"vul_id" uuid NOT NULL,
	CONSTRAINT "vul_score_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17118_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17118_2_not_null" CHECK (score IS NOT NULL),
	CONSTRAINT "2200_17118_3_not_null" CHECK (scoring_system IS NOT NULL),
	CONSTRAINT "2200_17118_4_not_null" CHECK (severity IS NOT NULL),
	CONSTRAINT "2200_17118_5_not_null" CHECK (vector IS NOT NULL),
	CONSTRAINT "2200_17118_6_not_null" CHECK (vul_id IS NOT NULL),
	CONSTRAINT "vul_id_fk" FOREIGN KEY (vul_id) REFERENCES "public"."vulnerability" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX vul_vector_uk ON public.vul_score USING btree (scoring_system, vector, vul_id);

set search_path to "public";
CREATE INDEX vul_vector_idx ON public.vul_score USING btree (vector);

CREATE TABLE "public"."vulnerability"(
	"id" uuid NOT NULL,
	"description" text NULL,
	"record_time" timestamptz NULL,
	"vul_id" text NULL,
	CONSTRAINT "vulnerability_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17102_1_not_null" CHECK (id IS NOT NULL)
);

set search_path to "public";
CREATE INDEX vul_id_idx ON public.vulnerability USING btree (vul_id);

set search_path to "public";
CREATE UNIQUE INDEX vul_uk ON public.vulnerability USING btree (vul_id);

CREATE TABLE "public"."sbom_creator"(
	"id" uuid NOT NULL,
	"name" text NOT NULL,
	"sbom_id" uuid NOT NULL,
	CONSTRAINT "sbom_creator_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17086_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17086_2_not_null" CHECK (name IS NOT NULL),
	CONSTRAINT "2200_17086_3_not_null" CHECK (sbom_id IS NOT NULL),
	CONSTRAINT "sbom_id_fk" FOREIGN KEY (sbom_id) REFERENCES "public"."sbom" (id)
);

set search_path to "public";
CREATE UNIQUE INDEX sbom_id_name_uk ON public.sbom_creator USING btree (sbom_id, name);

CREATE TABLE "public"."sbom_element_relationship"(
	"id" uuid NOT NULL,
	"related_element_id" text NOT NULL,
	"relationship_type" text NOT NULL,
	"comment" text NULL,
	"element_id" text NOT NULL,
	"sbom_id" uuid NOT NULL,
	CONSTRAINT "sbom_element_relationship_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_17094_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_17094_2_not_null" CHECK (related_element_id IS NOT NULL),
	CONSTRAINT "2200_17094_3_not_null" CHECK (relationship_type IS NOT NULL),
	CONSTRAINT "2200_17094_5_not_null" CHECK (element_id IS NOT NULL),
	CONSTRAINT "2200_17094_6_not_null" CHECK (sbom_id IS NOT NULL),
	CONSTRAINT "sbom_id_fk" FOREIGN KEY (sbom_id) REFERENCES "public"."sbom" (id)
);

set search_path to "public";
CREATE INDEX sbom_id_idx ON public.sbom_element_relationship USING btree (sbom_id);

set search_path to "public";
CREATE UNIQUE INDEX sbom_element_uk ON public.sbom_element_relationship USING btree (sbom_id, element_id, related_element_id, relationship_type);

set search_path to "public";
CREATE INDEX sbom_related_element_idx ON public.sbom_element_relationship USING btree (sbom_id, related_element_id);

CREATE TABLE "public"."file"(
	"id" uuid NOT NULL,
	"copyright_text" text NULL,
	"file_name" text NOT NULL,
	"file_types" _text NULL,
	"license_comments" text NULL,
	"license_concluded" text NULL,
	"license_info_in_files" _text NULL,
	"spdx_id" text NOT NULL,
	"sbom_id" uuid NOT NULL,
	CONSTRAINT "file_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_24615_1_not_null" CHECK (id IS NOT NULL),
	CONSTRAINT "2200_24615_3_not_null" CHECK (file_name IS NOT NULL),
	CONSTRAINT "2200_24615_8_not_null" CHECK (spdx_id IS NOT NULL),
	CONSTRAINT "2200_24615_9_not_null" CHECK (sbom_id IS NOT NULL),
	CONSTRAINT "sbom_id_fk" FOREIGN KEY (sbom_id) REFERENCES "public"."sbom" (id)
);

set search_path to "public";
CREATE INDEX file_name_idx ON public.file USING btree (sbom_id, file_name);

set search_path to "public";
CREATE UNIQUE INDEX file_uk ON public.file USING btree (sbom_id, spdx_id, file_name);

CREATE TABLE "public"."batch_job_instance"(
	"job_instance_id" int8 NOT NULL,
	"version" int8 NULL,
	"job_name" varchar(100) NOT NULL,
	"job_key" varchar(32) NOT NULL,
	CONSTRAINT "batch_job_instance_pkey" PRIMARY KEY ("job_instance_id"),
	CONSTRAINT "2200_16706_1_not_null" CHECK (job_instance_id IS NOT NULL),
	CONSTRAINT "2200_16706_3_not_null" CHECK (job_name IS NOT NULL),
	CONSTRAINT "2200_16706_4_not_null" CHECK (job_key IS NOT NULL)
);

set search_path to "public";
CREATE UNIQUE INDEX job_inst_un ON public.batch_job_instance USING btree (job_name, job_key);

CREATE TABLE "public"."package_vul_issue"(
	"cve_number" varchar NULL,
	"issue_id" varchar NULL,
	"issue_create_time" varchar NULL,
	"level" varchar NULL,
	"vul_status" varchar NULL,
	"issue_status" varchar NULL,
	"vul_awareness_duration" varchar NULL,
	"vul_patch_time" varchar NULL,
	"patch_release_time" varchar NULL,
	"cvss_score" varchar NULL,
	"nvd_score" varchar NULL,
	"software_name" varchar NULL,
	"complete_slo" varchar NULL,
	"issue_plan_complete_time" varchar NULL,
	"create_user" varchar NULL,
	"vul_release_time" varchar NULL,
	"vtopia_vul_release_time" varchar NULL,
	"sa_time" varchar NULL,
	"affect_branch" varchar NULL,
	"unaffected_branch" varchar NULL,
	"unanalyz_branch" varchar NULL,
	"organization_score" varchar NULL,
	"milestone" varchar NULL,
	"gitee_issue_url" varchar NULL,
	"issue_label" varchar NULL,
	"vtopia_recognition_time" varchar NULL,
	"affect_version" varchar NULL,
	"sig" varchar NULL,
	"team" varchar NULL,
	"charge_person" varchar NULL
);

CREATE TABLE "public"."batch_job_execution"(
	"job_execution_id" int8 NOT NULL,
	"version" int8 NULL,
	"job_instance_id" int8 NOT NULL,
	"create_time" timestamp NOT NULL,
	"start_time" timestamp NULL,
	"end_time" timestamp NULL,
	"status" varchar(10) NULL,
	"exit_code" varchar(2500) NULL,
	"exit_message" varchar(2500) NULL,
	"last_updated" timestamp NULL,
	"job_configuration_location" varchar(2500) NULL,
	CONSTRAINT "batch_job_execution_pkey" PRIMARY KEY ("job_execution_id"),
	CONSTRAINT "2200_16713_1_not_null" CHECK (job_execution_id IS NOT NULL),
	CONSTRAINT "2200_16713_3_not_null" CHECK (job_instance_id IS NOT NULL),
	CONSTRAINT "2200_16713_4_not_null" CHECK (create_time IS NOT NULL),
	CONSTRAINT "job_inst_exec_fk" FOREIGN KEY (job_instance_id) REFERENCES "public"."batch_job_instance" (job_instance_id)
);

CREATE TABLE "public"."batch_step_execution_context"(
	"step_execution_id" int8 NOT NULL,
	"short_context" varchar(2500) NOT NULL,
	"serialized_context" text NULL,
	CONSTRAINT "batch_step_execution_context_pkey" PRIMARY KEY ("step_execution_id"),
	CONSTRAINT "2200_16747_1_not_null" CHECK (step_execution_id IS NOT NULL),
	CONSTRAINT "2200_16747_2_not_null" CHECK (short_context IS NOT NULL),
	CONSTRAINT "step_exec_ctx_fk" FOREIGN KEY (step_execution_id) REFERENCES "public"."batch_step_execution" (step_execution_id)
);

CREATE TABLE "public"."product_vul_ref"(
	"id" uuid NOT NULL,
	"download_location" text NULL,
	"name" text NULL,
	"vul_id" text NULL,
	"issue_id" text NULL,
	"issue_status" text NULL,
	"vul_status" text NULL,
	CONSTRAINT "product_vul_ref_pkey" PRIMARY KEY ("id"),
	CONSTRAINT "2200_80374_1_not_null" CHECK (id IS NOT NULL)
);





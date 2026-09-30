-- Initial PostgreSQL schema. SQLAlchemy models are authoritative for release 1.

CREATE TABLE audit_logs (
	id VARCHAR(36) NOT NULL, 
	actor VARCHAR(100) NOT NULL, 
	action VARCHAR(60) NOT NULL, 
	subject VARCHAR(100) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
)

;

CREATE TABLE domains (
	name VARCHAR(253) NOT NULL, 
	first_seen TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (name)
)

;

CREATE TABLE url_entities (
	key VARCHAR(64) NOT NULL, 
	domain VARCHAR(253) NOT NULL, 
	display TEXT NOT NULL, 
	PRIMARY KEY (key), 
	FOREIGN KEY(domain) REFERENCES domains (name)
)

;
CREATE INDEX ix_url_entities_domain ON url_entities (domain);

CREATE TABLE investigations (
	id VARCHAR(36) NOT NULL, 
	url_key VARCHAR(64) NOT NULL, 
	owner VARCHAR(100) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	mode VARCHAR(10) NOT NULL, 
	report JSONB NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(url_key) REFERENCES url_entities (key)
)

;
CREATE INDEX ix_investigations_owner ON investigations (owner);
CREATE INDEX ix_investigations_created_at ON investigations (created_at);
CREATE INDEX ix_investigations_url_key ON investigations (url_key);

CREATE TABLE analyst_verifications (
	id VARCHAR(36) NOT NULL, 
	investigation_id VARCHAR(36) NOT NULL, 
	verdict VARCHAR(20) NOT NULL, 
	analyst VARCHAR(100) NOT NULL, 
	note TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(investigation_id) REFERENCES investigations (id)
)

;
CREATE INDEX ix_analyst_verifications_investigation_id ON analyst_verifications (investigation_id);

CREATE TABLE user_feedback (
	id VARCHAR(36) NOT NULL, 
	investigation_id VARCHAR(36) NOT NULL, 
	owner VARCHAR(100) NOT NULL, 
	category VARCHAR(30) NOT NULL, 
	note TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(investigation_id) REFERENCES investigations (id)
)

;
CREATE INDEX ix_user_feedback_investigation_id ON user_feedback (investigation_id);

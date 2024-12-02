CREATE TABLE toverflow(id SERIAL, col1 VARCHAR);
INSERT INTO toverflow VALUES (default, 'hope') RETURNING xmax::text::int;
INSERT INTO toverflow VALUES (default, 'jack') RETURNING xmax;
SELECT * FROM toverflow ORDER BY id;
DROP TABLE toverflow;

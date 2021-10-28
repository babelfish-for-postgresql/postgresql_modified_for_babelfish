-- [BABEL-2370] - Preserve case of unquoted column names and alias names in the output columns of a top-level SELECT
CREATE EXTENSION IF NOT EXISTS babelfishpg_tsql CASCADE;
SET babelfishpg_tsql.sql_dialect = 'tsql';
CREATE SCHEMA ts;
CREATE TABLE ts.t1 (ABC text, b varchar(20), c char(4), Xyz int, "Delimited" int, "Special Chars" bigint);

SELECT * from ts.t1;
SELECT xyz, XYZ, xYz, xyz ColName, xYz AS ColName, "Special Chars", "Delimited", "DeLIMITed" from ts.t1;

SELECT xyz AS "WOW! This is a very very long identifier that will get truncated with a uniquifying suffix by Babelfish" from ts.t1;
SELECT xyz AS "WOW! This is a very very long identifier that will get truncated with a uniquifying suffix by Babelfish - with extra stuff at the end" from ts.t1;

RESET babelfishpg_tsql.sql_dialect;
DROP EXTENSION babelfishpg_tsql CASCADE;
DROP SCHEMA ts CASCADE;

#!/bin/bash

db_file=$1


cat << EOF | sqlite3 $db_file
PRAGMA synchronous = OFF;
PRAGMA cache_size = 800000;
PRAGMA journal_mode = OFF;
PRAGMA count_changes = OFF;
PRAGMA temp_store = MEMORY;
PRAGMA locking = EXCLUSIVE;

CREATE INDEX caller_fn_idx on caller_info (function, call_id);
CREATE INDEX caller_ff_idx on caller_info (file, function, call_id);
CREATE INDEX call_implies_fn_idx on call_implies (function);
CREATE INDEX call_implies_ff_idx on call_implies (file, function);
CREATE INDEX data_file_info_idx on data_info (file, data);
CREATE INDEX data_info_idx on data_info (data);
CREATE INDEX fn_ptr_idx_file on function_ptr (file, function);
CREATE INDEX fn_ptr_idx_nofile on function_ptr (function);
CREATE INDEX fn_ptr_idx_ptr on function_ptr (ptr);
CREATE INDEX file_function_type_info_idx on function_type_info (file, function);
CREATE INDEX function_type_info_idx on function_type_info (function);
CREATE INDEX function_type_size_idx ON function_type_size (type);
CREATE INDEX function_type_value_idx ON function_type_value (type);
CREATE INDEX local_value_idx on local_values (file, variable);
CREATE INDEX return_states_fn_idx on return_states (function);
CREATE INDEX return_states_ff_idx on return_states (file, function);

EOF

#CREATE INDEX type_size_idx on type_size (type);
#CREATE INDEX type_val_idx on type_value (type);


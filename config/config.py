import signal


FUZZER_CONFIG = {
    'path': {
        'input_path': './test/example_inputs',
        'output_path': './test/output',
        'binary_path': './test/binaries',
    },

    'termination_conditions': {
        'signals': [signal.SIGSEGV, signal.SIGILL],
        'signal_output_combinations': {
            signal.SIGABRT: [b'stack smashing', b'heap',
                             b'overflow', b'double free', b'tcache']
        }
    },

    'mime_type_mapping': {
        'text/plain': 'plaintext',
        'application/json': 'json',
        'text/csv': 'csv',
        'image/jpeg': 'jpg',
        'text/html': 'xml',
        'application/pdf': 'pdf',
        'application/x-pie-executable': 'elf',
        'application/x-executable': 'elf',
    },

    'binary_timeout_seconds': 60,
    'test_case_timeout_seconds': 1,


    'coverage': {
        'enabled': False,
        'improvement_threshold': 0.02,
        'skip_functions': ['__do_global_dtors_aux', '_init', '_start', 'deregister_tm_clones', 'frame_dummy', 'register_tm_clones', '.plt', '_fini', '.text', '.init', '.fini']
        # skip .text because this means the binary is statically compiled
    },
    'mutator': {
        'interesting_ints': [
            0, 1, -1, 2, -2, 4, -4, 8, -8, 16, -16, 32, -32, 64, -64,
            128, -128, 256, -256, 512, -512, 1024, -1024, 2048, -2048,
            0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
            0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
            0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff
        ],

        'interesting_strings': [
            b"", b"a", b"A", b"0", b"1", b"true", b"false", b"null",
            b"admin", b"root", b"user", b"test", b"password", b"pass",
            b"../../", b"../", b"./", b"/", b"\\", b"\\\\",
            b"<script>", b"</script>", b"<", b">", b"&", b"\"", b"'",
            b"%00", b"%01", b"%02", b"%03", b"%04", b"%05",
            b"\x00", b"\x01", b"\x02", b"\x03", b"\x04", b"\x05",
            b"\xff", b"\xfe", b"\xfd", b"\xfc", b"\xfb",
            b"A" * 100, b"A" * 1000, b"A" * 10000,
            b"\x00" * 100, b"\xff" * 100 ,b"%n", b"AAAA%n", b"%x%x%x%x", b"%s%s%s%s", b"%p", b"%p%p%p%p", b"%x.%x.%x.%x", b"%d.%d.%d.%d",
            b"%1$p", b"%2$p", b"%3$p", b"%7$p", b"%8$p", b"%9$p", b"%10$p", b"%11$p",
            b"%5$s", b"%7$s", b"%10$s", b"BBBB%7$n", b"CCCC%8$n", b"DDDD%12$n",
            b"%s", b"%d", b"%n" * 10, b"%n" * 100, b"%.10000s", b"%.10000d", b"%.10000x",
            b"%*10000d", b"%x.%p.%d.%s.%n", b"||%p||%p||%p||",
            b"%c", b"%h", b"%hn", b"%hhn", b"%lln", b"%lf", b"%f"
        ],

        'strategy_weights': {
            'bit_flip': 0.12,
            'byte_flip': 0.12,
            'arithmetic': 0.12,
            'interesting_int': 0.10,
            'interesting_string': 0.10,
            'repeat_or_truncate': 0.10,
            'splice': 0.10,
            'dictionary': 0.10,
            'format_specific': 0.08,
            'extreme_values': 0.06
        }
    },
    'csv_template': {
        'max_cases': 2000,
        'mutations_per_cell': 5,
        'mutations_per_row': 5,
        'whole_file_mutations': 2000,
        'take_from_whole_file': 800
    },
    'json_template': {
        'strategy_weights': {
            'mutate_values': 0.2,
            'mutate_keys': 0.15,
            'mutate_key_value_pairs': 0.15,
            'add_or_delete_pairs': 0.15,
            'structure_mutation': 0.1,
            'add_multiple_pairs': 0.15,
            'add_deep_nesting': 0.1
        },
        'max_mutations_per_strategy': 3,
        'max_pairs_to_add': 1000,
        'max_nesting_depth': 10
    },
    'jpg_template': {
        'strategy_weights': {
            'mutate_structure_integers': 0.4,
            'mutate_segment_size': 0.2,
            'mutate_entropy_data': 0.3,
            'shuffle_segments': 0.1
        },
        'interesting_integers': [
            0, 1, 255, 256, 32767, 32768, 65535,
            60000, 23861 
        ],
        'max_segment_expansion': 4096
    },
}

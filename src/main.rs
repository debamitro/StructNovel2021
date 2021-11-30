use c_introspect_rs::c_parser::parse_c_file;
use std::env;
use std::fs;

fn describe_struct(number_of_fields: usize) -> &'static str {
    if number_of_fields > 5 {
        "formidable"
    } else if number_of_fields > 3 {
        "mighty"
    } else if number_of_fields > 0 {
        "tiny"
    } else {
        "empty"
    }
}

fn generate_chapter_from_header_file(chapter_num: i32, pathstr: &str) {
    println!("## Chapter {}\n", chapter_num);
    if let Some(itr) = parse_c_file(pathstr) {
        println!("One fine day our hero ventured into {}\n", pathstr);

        let mut foundsomestructs = false;

        for cstruct in itr {
            println!(
                "He conquered the {} struct {}",
                describe_struct(cstruct.fields.len()),
                &cstruct.name
            );
            for cfield in cstruct.fields {
                println!("It had a {} called {}", &cfield.typename, &cfield.name);
            }
            foundsomestructs = true;
        }

        if !foundsomestructs {
            println!("Alas, he found nothing at all and came back empty-handed");
        }
    }
    println!("");
}

fn find_header_files(directory: &str, process_header_file: fn(i32, &str) -> ()) {
    let mut chapter_num: i32 = 0;
    if let Ok(itr) = fs::read_dir(directory) {
        for e in itr {
            if let Ok(entry) = e {
                if let Ok(m) = entry.metadata() {
                    if m.is_file() {
                        if let Some(s) = entry.file_name().to_str() {
                            if s.ends_with(".h") {
                                if let Some(pathstr) = entry.path().to_str() {
                                    chapter_num += 1;
                                    process_header_file(chapter_num, pathstr);
                                }
                            }
                        }
                    } else if m.is_dir() {
                        if let Some(pathstr) = entry.path().to_str() {
                            find_header_files(pathstr, process_header_file);
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        println!("# Structs of {}\n", &arg1);
        find_header_files(&arg1, generate_chapter_from_header_file);
    } else {
        println!(
            "usage is: {} <path-to-/usr/include>",
            env::args().nth(0).unwrap()
        );
    }
}

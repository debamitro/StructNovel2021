use c_introspect_rs::c_parser::parse_c_file;
use std::env;
use std::fs;

fn describe_struct(number_of_fields: usize) -> &'static str {
    if number_of_fields > 5 {
        "formidable"
    } else if number_of_fields > 3 {
        "mighty"
    } else if number_of_fields > 0 {
        "_puny_"
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
            let mut firstfield = true;
            for cfield in cstruct.fields {
                if firstfield {
                    print!(" which had");
                    firstfield = false;
                } else {
                    print!(", and");
                }
                println!(" a {} called {}", &cfield.typename, &cfield.name);
            }
            foundsomestructs = true;
        }

        if !foundsomestructs {
            println!("Alas, he found nothing at all and came back empty-handed");
        }
    }
    println!("");
}

fn find_header_files(directory: &str, process_header_file: fn(i32, &str) -> ()) -> i32 {
    find_next_n_header_files(0, directory, process_header_file)
}

fn find_next_n_header_files(
    files_found_so_far: i32,
    directory: &str,
    process_header_file: fn(i32, &str) -> (),
) -> i32 {
    let mut file_number: i32 = files_found_so_far;
    if let Ok(itr) = fs::read_dir(directory) {
        for e in itr {
            if let Ok(entry) = e {
                if let Ok(m) = entry.metadata() {
                    if m.is_file() {
                        if let Some(s) = entry.file_name().to_str() {
                            if s.ends_with(".h") {
                                if let Some(pathstr) = entry.path().to_str() {
                                    file_number += 1;
                                    process_header_file(file_number, pathstr);
                                }
                            }
                        }
                    } else if m.is_dir() {
                        if let Some(pathstr) = entry.path().to_str() {
                            file_number =
                                find_next_n_header_files(file_number, pathstr, process_header_file);
                        }
                    }
                }
            }
        }
    }

    return file_number;
}

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        println!("# Structs of {}\n", &arg1);
        println!("\n## Introduction\n");
        println!("This is the story of a brave knight who ventured into {} in an attempt to conquer all the C structs he could find there\n", &arg1);
        find_header_files(&arg1, generate_chapter_from_header_file);
    } else {
        println!(
            "usage is: {} <path-to-/usr/include>",
            env::args().nth(0).unwrap()
        );
    }
}

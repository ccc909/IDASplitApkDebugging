import ida_idaapi
import ida_kernwin
import ida_dbg
import ida_segment
import ida_bytes
import ida_nalt
import zipfile
import os
import io
import hashlib
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

class ApkSegmentRenamerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Remaps segment names in the debugger based on content matching and offers rebasing"
    help = """
    This plugin should be run during a debugging session.
    This plugin parses their ELF headers,
    renames matching debugger segments based on content (code segment hashes), and offers to rebase if the currently loaded
    file matches any of the renamed segments.

    Requires the 'pyelftools' library. Install it via: pip install pyelftools
    """
    wanted_name = "Segment renamer with Rebasing"
    wanted_hotkey = ""

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def term(self):
        pass
    
    # Get IDA currently loaded file 
    def get_current_file_name(self):
        input_file = ida_nalt.get_input_file_path()
        if input_file:
            return os.path.basename(input_file)
        return None

    def offer_rebase(self, target_filename, renamed_segments):
        matching_segments = []
        for seg_info in renamed_segments:
            seg, new_name = seg_info
            if target_filename.lower() in new_name.lower():
                matching_segments.append((seg, new_name))

        if not matching_segments:
            return

        if len(matching_segments) == 1:
            seg, seg_name = matching_segments[0]
            msg = f"Found matching segment '{seg_name}' for loaded file '{target_filename}'.\n"
            msg += f"Would you like to rebase the database to address {seg.start_ea:#010x}?"

            if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, msg) == ida_kernwin.ASKBTN_YES:
                self.perform_rebase(seg.start_ea, target_filename)
        else:
            chooser_title = f"Multiple segments match '{target_filename}'. Select one to rebase:"
            chooser_items = [
                [seg_name, f"{seg.start_ea:#010x}"] for seg, seg_name in matching_segments
            ]
            
            chooser_cols = [
                ["Segment Name", 40],
                ["Start Address", 20]
            ]

            c = ida_kernwin.Choose(chooser_items, chooser_title, cols=chooser_cols, flags=ida_kernwin.Choose.CH_MODAL)
            chosen_index = c.Show()

            if chosen_index >= 0:
                seg, seg_name = matching_segments[chosen_index]
                ida_kernwin.msg(f"User selected '{seg_name}' for rebasing.\n")
                self.perform_rebase(seg.start_ea, target_filename)
            else:
                ida_kernwin.msg("Rebasing cancelled by user.\n")

    # IDA rebase wrapper with logging
    def perform_rebase(self, new_base, filename):
        try:
            current_base = ida_nalt.get_imagebase()
            delta = new_base - current_base
            
            ida_kernwin.msg(f"Rebasing '{filename}' from {current_base:#010x} to {new_base:#010x} (delta: {delta:#x})...\n")

            ida_segment.rebase_program(delta, ida_segment.MSF_NOFIX)
            ida_kernwin.msg(f"Successfully rebased to {new_base:#010x}\n")

        except Exception as e:
            ida_kernwin.warning(f"Error during rebasing: {e}")

    def run(self, arg):
        if not ida_dbg.is_debugger_on():
            ida_kernwin.warning("This plugin is designed to be run during a debugging session.\n"
                                "Please start debugging and pause the process before running it.")
            return

        apk_path = ida_kernwin.ask_file(False, "*.apk", "Select the corresponding APK file")

        if not apk_path:
            ida_kernwin.msg("No file selected. Aborting.\n")
            return

        current_file = self.get_current_file_name()
        if current_file:
            ida_kernwin.msg(f"Currently loaded file: {current_file}\n")
        else:
            ida_kernwin.msg("Could not determine the currently loaded file name.\n")

        ida_kernwin.msg(f"Analyzing {os.path.basename(apk_path)} for libraries...\n")

        code_hash_to_so_info = {}
        so_files_found = 0

        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for item in apk_zip.infolist():
                    if (item.is_dir() or item.file_size < 1024 or
                            not item.filename.startswith('lib/arm') or # Good enough for my uses cases, change this if it doesnt catch your use case
                            not item.filename.lower().endswith('.so')):
                        continue

                    so_files_found += 1
                    ida_kernwin.msg(f"Processing library: {item.filename}\n")

                    try:
                        so_bytes = apk_zip.read(item.filename)
                        stream = io.BytesIO(so_bytes)
                        elffile = ELFFile(stream)

                        # Find the main executable code segment
                        code_seg_header = None
                        for seg in elffile.iter_segments():
                            if seg.header.p_type == 'PT_LOAD' and seg.header.p_flags & 0x1:  # PF_X (Executable)
                                code_seg_header = seg.header
                                break

                        if code_seg_header and code_seg_header.p_filesz > 0:
                            # Hash the first 1024 bytes of the code segment for identification
                            N = min(1024, code_seg_header.p_filesz)
                            code_bytes = so_bytes[code_seg_header.p_offset:code_seg_header.p_offset + N]
                            code_hash = hashlib.sha256(code_bytes).hexdigest()
                            
                            
                            code_hash_to_so_info[code_hash] = {
                                'filename': item.filename,
                                'basename': os.path.basename(item.filename),
                                'segments': [(s.header.p_offset, s.header.p_filesz, s.header.p_memsz, s.header.p_vaddr, s.header.p_flags)
                                             for s in elffile.iter_segments() if s.header.p_type == 'PT_LOAD']
                            }
                        else:
                            ida_kernwin.msg(f"Warning: No valid code segment in {item.filename}. Skipping.\n")

                    except ELFError:
                        ida_kernwin.msg(f"Warning: Could not parse ELF for {item.filename}. Skipping.\n")
                    except Exception as e:
                        ida_kernwin.msg(f"Error processing {item.filename}: {e}\n")

        except zipfile.BadZipFile:
            ida_kernwin.warning(f"Error: The selected file '{apk_path}' is not a valid APK/ZIP file.")
            return
        except Exception as e:
            ida_kernwin.warning(f"An unexpected error occurred while reading the APK: {e}")
            return

        if not code_hash_to_so_info:
            ida_kernwin.info("No valid .so files with code segments found in the APK.")
            return

        ida_kernwin.msg(f"Found {so_files_found} libraries to process.\n")

        # Step 2: Scan debugger segments and match them using content hashes
        renamed_count = 0
        renamed_segments = []
        num_segments = ida_segment.get_segm_qty()

        for i in range(num_segments):
            seg = ida_segment.getnseg(i)
            if not seg:
                continue

            seg_size = seg.end_ea - seg.start_ea
            N = min(1024, seg_size)  # Use the same sample size for hashing
            
            # Skip if segment is too small for a meaningful hash
            if N < 1024:
                continue

            seg_bytes = ida_bytes.get_bytes(seg.start_ea, N)
            if not seg_bytes:
                continue

            seg_hash = hashlib.sha256(seg_bytes).hexdigest()

            if seg_hash in code_hash_to_so_info:
                so_info = code_hash_to_so_info[seg_hash]
                base_name = so_info['basename']
                matched_seg_base = seg.start_ea
                
                ida_kernwin.msg(f"Matched '{base_name}' based on code segment at {matched_seg_base:#010x}.\n")

                # Step 3: Rename all segments belonging to the matched library
                code_vaddr_in_elf = next((s[3] for s in so_info['segments'] if s[4] & 0x1), None)
                if code_vaddr_in_elf is None:
                    continue # Should not happen if we matched it
                
                name_counters = defaultdict(int)

                for _, _, _, p_vaddr, p_flags in so_info['segments']:
                    is_code = p_flags & 0x1  # PF_X
                    seg_type = "code" if is_code else "data"
                    base_new_name = f"{base_name}_{seg_type}"
                    
                    count = name_counters[base_new_name]
                    name_counters[base_new_name] += 1
                    new_name = f"{base_new_name}_{count}" if count > 0 else base_new_name
                    
                    # Calculate the expected start address of this segment in the debugger memory
                    relative_offset = p_vaddr - code_vaddr_in_elf
                    expected_ea = matched_seg_base + relative_offset
                    
                    target_seg = ida_segment.getseg(expected_ea)
                    if not target_seg:
                        # Account for alignment difference
                        target_seg = ida_segment.getseg(ida_nalt.get_prev_head(expected_ea + 1))
                    
                    if target_seg and abs(target_seg.start_ea - expected_ea) < 4096: # Allow page-size tolerance
                        old_name = ida_segment.get_segm_name(target_seg)
                        if old_name != new_name:
                             if ida_segment.set_segm_name(target_seg, new_name):
                                ida_kernwin.msg(f"  - Renamed segment at {target_seg.start_ea:#010x} from '{old_name}' to '{new_name}'\n")
                                renamed_count += 1
                                if is_code:
                                    renamed_segments.append((target_seg, new_name))
                
                # Remove the matched hash to prevent reprocessing if another memory segment has identical content
                del code_hash_to_so_info[seg_hash]


        ida_kernwin.msg(f"\nFinished. Renamed {renamed_count} segment(s).\n")
        ida_kernwin.msg("Refresh the Segments window to see changes.\n")

        # Step 4: Offer to rebase the database if the currently loaded file was among the renamed segments
        if current_file and renamed_segments:
            ida_kernwin.msg(f"Checking if '{current_file}' matches any renamed segments for rebasing...\n")
            self.offer_rebase(current_file, renamed_segments)

def PLUGIN_ENTRY():
    return ApkSegmentRenamerPlugin()
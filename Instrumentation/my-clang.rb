#!/usr/bin/env ruby

# This is a wrapper script around clang, ar, ranlib, etc., to perform the
# different  compilation steps (Modified version of ASAP's wrapper):
#
#
# Please see LICENSE.txt for copyright and licensing information.

require 'fileutils'
# require 'parallel'
require 'pathname'
require 'singleton'
require_relative 'my_clang_utils.rb'

$generate_profiling_info=false
$compiler_state_env_name= "OPTISAN_COMPILER_STATE"
$generate_profiling_info_env_name= "OPTISAN_REQ_COVERAGE"


class CompilerState

  attr_reader :value

  def initialize(value)
    @value = value
  end

  ASanFull = CompilerState.new("ASanFull")
  ASanNoChecks = CompilerState.new("ASanNoChecks")
  ASanStackMD = CompilerState.new("ASanStackMD")
  BaggyFull = CompilerState.new("BaggyFull")
  BaggyNoChecks = CompilerState.new("BaggyNoChecks")
  BaggyStackMD = CompilerState.new("BaggyStackMD")
  PlacementMode = CompilerState.new("PlacementMode")
  BaseMode = CompilerState.new("BaseMode")

end  

# This class keeps track of the state of the ASAP compilation. It maintains the
# current state, compilation output files, ...
class AsapState
  include Singleton

  # Singleton design
  def initialize()
    @current_state=:initial
  end

  # Creates the right compiler for the given state
  def create_compiler()
    if current_state == :initial
      BaseCompiler.new(self)
    elsif current_state == :optbase
      OptBaseCompiler.new(self)
    elsif current_state== :asan
      ASANProfilingCompiler.new(self)
    elsif current_state == :baggy
      BaggyBoundsProfilingCompiler.new(self)
    elsif current_state== :place
      PlacementCompiler.new(self)
    elsif current_state==:baggyasan
      BaggyASANProfilingCompiler.new(self)
    else
      raise "Unknown state: #{current_state}"
    end
  end

  # Getter method for the state
  def current_state
    @current_state
  end

  # Setter method
  def current_state=(state)
    @current_state = state
  end

  def transition(from, to)
    self.current_state = to
  end

  private :current_state

end


# This is a base class for executing compilation steps. The default behavior is
# to forward the commands to the original clang/ar/ranlib.
class BaseCompiler
  attr_reader :state

  def initialize(state)
    @state = state
  end

  def exec(cmd)
    command_type = get_command_type(cmd)
    if command_type == :compile
      do_compile(cmd)
    elsif command_type == :link
      do_link(cmd)
    elsif command_type == :ar
      do_ar(cmd)
    elsif command_type == :ranlib
      do_ranlib(cmd)
    else
      raise "invalid command: #{cmd}"
    end
  end

  def get_command_type(cmd)
    if cmd[0] =~ /(?:my-|\/)clang(?:\+\+)?$/
      if get_arg(cmd, '-c', :first)
        return :compile
      else
        return :link
      end
    elsif cmd[0] =~ /(?:my-|\/)ar$/
      return :ar
    elsif cmd[0] =~ /(?:my-|\/)ranlib$/
      return :ranlib
    end
  end

  def do_compile(cmd)
    cmd = [find_clang()] + cmd[1..-1]
    run!(*cmd)
  end
  def do_link(cmd)
    cmd = [find_clang()] + cmd[1..-1]
    run!(*cmd)
  end
  def do_ar(cmd)
    puts "Base ar"
    cmd = [find_ar()] + cmd[1..-1]
    run!(*cmd)
  end
  def do_ranlib(cmd)
    puts "Base ranlib"
    cmd = [find_ar(), '-s'] + cmd[1..-1]
    run!(*cmd)
  end
end


# Compiler which does not do all front end optimizations. Better design would be to hook into pipeline early and find necessary instructions (probably deal with inlining)
class OptBaseCompiler < BaseCompiler

  def do_compile(cmd)
    target_name = get_arg(cmd, '-o')
    clang = find_clang()

    return super unless target_name and target_name.end_with?('.o')

    # Step 1 - Build the bitcode file
    if target_name and target_name.end_with?('.o')
      begin
        clang_args = cmd[1..-1]

        clang_args = insert_arg(clang_args, '-flto')

        if target_name.end_with?('.o')
          bitcode_target_name= mangle(target_name, '.o', '.bc.o')
        elsif target_name.end_with?('.lo')
          bitcode_target_name= mangle(target_name, '.lo', '.bc.lo')
        elsif target_name.end_with?('.la')
          bitcode_target_name= mangle(target_name, '.la', '.bc.la')
        end
 
        if $generate_profiling_info
          gcno_name = mangle(target_name, '.o', '.gcno')
          gcda_name = mangle(target_name, '.o', '.gcda')
          # clang_args = insert_arg(clang_args, '-gline-tables-only')
          # Not adding coverage notes adds one BB (which I think is the last BB). WIP. Seems to be working
          #clang_args = ['-Xclang', '-femit-coverage-notes'] + clang_args
          clang_args = ['-Xclang', "-coverage-data-file=#{gcda_name}"] + clang_args
          clang_args = ['-Xclang', "-coverage-notes-file=#{gcno_name}"] + clang_args
        elsif 
          optimization_level=clang_args.select { |clang_arg| clang_arg.include?('-O')}
          unless optimization_level.empty?
            optimization_level_arg_pos=clang_args.find_index(optimization_level.first)
            clang_args[optimization_level_arg_pos]='-O0'
            # clang_args = clang_args.insert(optimization_level_arg_pos+1, '-Xclang')
            # clang_args = clang_args.insert(optimization_level_arg_pos+2, '-disable-O0-optnone')
            # clang_args[optimization_level_arg_pos]='-O1'
            # clang_args = clang_args.insert(optimization_level_arg_pos+1, '-Xclang')
            # clang_args = clang_args.insert(optimization_level_arg_pos+2, '-disable-llvm-passes')
          end
        end  
        run!(clang, *clang_args)

        if not $generate_profiling_info
          run!(find_opt(), '-load',find_sanitization_helper_pass(),'-pre-sanitize','-o',target_name,target_name)
        end

        opt_level = get_optlevel_for_llc(cmd)
        run!(find_opt(),opt_level,'-o', bitcode_target_name,target_name)

        # Optional step (if specified) - Instrument the resulting bitcode file for coverage
        if $generate_profiling_info
          run!(find_opt(),'-insert-gcov-profiling','-o', bitcode_target_name,bitcode_target_name)
        end

        # Covert it into an object file
        opt_level = get_optlevel_for_llc(cmd)
        run!(find_llc(),opt_level,'-optimize-regalloc', '-filetype=obj', '-relocation-model=pic','-o', target_name, bitcode_target_name)

      rescue RunExternalCommandError
        # Nothing to do...
      end
    end
  end

  def do_link(cmd)
    linker_args = cmd[1..-1]
    if $generate_profiling_info
     linker_args = insert_arg(linker_args, '-coverage')
    end
    super([cmd[0]] + linker_args)
  end
end



# Compiler with ASAN and profiling information.
class ASANProfilingCompiler < BaseCompiler

  def do_compile(cmd)
    target_name = get_arg(cmd, '-o')
    clang = find_clang()

    return super unless target_name and target_name.end_with?('.o')

    if target_name and target_name.end_with?('.o')
      begin

        # Step 1 - Convert to bitcode and run desired passes aka ASAN and then convert to object file
        clang_args = cmd[1..-1]
        clang_args = insert_arg(clang_args, '-flto')

        if $generate_profiling_info
          gcno_name = mangle(target_name, '.o', '.gcno')
          gcda_name = mangle(target_name, '.o', '.gcda')
          # Not adding coverage notes adds one BB (which I think is the last BB). WIP. Seems to be working
          # clang_args = ['-Xclang', '-femit-coverage-notes'] + clang_args
          # I had added these options earlier when I was modifying asap-clang
          clang_args = ['-Xclang', "-coverage-data-file=#{gcda_name}"] + clang_args
          clang_args = ['-Xclang', "-coverage-notes-file=#{gcno_name}"] + clang_args
          # This apparently turns off macro dbg info even if that explicit flag is specified
          # clang_args = insert_arg(clang_args, '-gline-tables-only')
        end

        run!(clang, *clang_args)

        bitcode_target_name= mangle(target_name, '.o', '.bc.o')

        # Cost estimation (If we want to run ASAN normally can just use explicit flag)
        # Step 2 - Instrument the resulting bitcode file  with ASAN (We added this because it makes it easier to turn off globals etc)
        run!(find_opt(),'-load',find_sanitization_helper_pass(),'-pre-sanitize','-o',bitcode_target_name,target_name)

        if $compiler_state_env == CompilerState::ASanFull.value
          # Normal ASAN
          # run!(find_opt(),'-asan','-asan-module','-o',bitcode_target_name,bitcode_target_name)
          # Not sanity check - No halt on error
          run!(find_opt(),'-asan','-asan-module','-asan-recover=true','-o',bitcode_target_name,bitcode_target_name)
        else
          if  $compiler_state_env == CompilerState::ASanNoChecks.value
                  # Normal ASAN
                  # puts "ASAN_NO_STACK"
                  run!(find_opt(),'-asan','-asan-module','-o',bitcode_target_name,bitcode_target_name)
                  # Not sanity check - No halt on error
                  #run!(find_opt(),'-asan','-asan-module','-asan-recover=true','-o',bitcode_target_name,bitcode_target_name)  
        
          elsif $compiler_state_env == CompilerState::ASanStackMD.value  
                  # Stack md only - This is to turn off unnecessary classes of operations such as heap metadata, globals etc    
                  # PS - Use pre sanitization pass (TEST MODE) to annotate functions and turned off heap by changing source code and recompiling, explicitly turn off globals
                  run!(find_opt(),'-asan','-asan-module','-asan-globals=false','-o',bitcode_target_name,bitcode_target_name)
                  # Asan stack md only + Not sanity check - No halt on error + No globals 
                  # run!(find_opt(),'-asan','-asan-module','-asan-globals=false','-asan-recover=true','-o',bitcode_target_name,bitcode_target_name)
          end  
          # Turn off checks
          run!(find_opt(),'-load',find_tce_pass(),'-tce','-dce','-simplifycfg','-o', bitcode_target_name,bitcode_target_name)
        end  
        # Optimize IR as specified
        opt_level = get_optlevel_for_llc(cmd)
        # I think LLC is machine specific and backend passes, whereas opt is machine independent middle end passes and normally optimization level would run both so this is needed
        run!(find_opt(),'-dce','-simplifycfg',opt_level,'-o', bitcode_target_name,bitcode_target_name)

        # Optional step (if specified) - Instrument the resulting bitcode file for coverage
        if $generate_profiling_info
          run!(find_opt(),'-insert-gcov-profiling','-o', bitcode_target_name,bitcode_target_name)
        end

        # Step 3 - Covert it into an object file
        opt_level = get_optlevel_for_llc(cmd)
        run!(find_llc(),opt_level, '-filetype=obj', '-relocation-model=pic','-o', target_name, bitcode_target_name)

      rescue RunExternalCommandError
        # Nothing to do...
      end
    end
  end

  def do_link(cmd)
    linker_args = cmd[1..-1]
    linker_args = insert_arg(linker_args,"-fsanitize=address")
    if $generate_profiling_info
      linker_args = insert_arg(linker_args, '-coverage')
      #log("Profiling compiler linker args: #{linker_args}")
    end
    super([cmd[0]] + linker_args)
  end
end

# Compiler with Baggy bounds and profiling information.
class BaggyBoundsProfilingCompiler < BaseCompiler

  def do_compile(cmd)
    target_name = get_arg(cmd, '-o')
    clang = find_clang()

    return super unless target_name and target_name.end_with?('.o')

    if target_name and target_name.end_with?('.o')
      begin
        # Step 1 - Convert to bitcode and run desired passes and then convert to object file
        clang_args = cmd[1..-1]
        clang_args = insert_arg(clang_args, '-flto')

        if $generate_profiling_info
          gcno_name = mangle(target_name, '.o', '.gcno')
          gcda_name = mangle(target_name, '.o', '.gcda')
          # This apparently turns off macro dbg info even if that explicit flag is specified
          # clang_args = insert_arg(clang_args, '-gline-tables-only')
          # Not adding coverage notes adds one BB (which I think is the last BB). WIP. Seems to be working
          #clang_args = ['-Xclang', '-femit-coverage-notes'] + clang_args
          # I had added these options earlier when I was modifying asap-clang
          clang_args = ['-Xclang', "-coverage-data-file=#{gcda_name}"] + clang_args
          clang_args = ['-Xclang', "-coverage-notes-file=#{gcno_name}"] + clang_args
        end

        run!(clang, *clang_args)

        # Step 2 - Instrument the resulting bitcode file  (Baggy bounds)
        bitcode_target_name= mangle(target_name, '.o', '.bc.o')
        run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds', "-baggy-save-local",'-baggy-pointers','-o', bitcode_target_name,target_name)

        if $compiler_state_env == CompilerState::BaggyFull.value
          # Baggy normal
          run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds', "-baggy-save-local",'-baggy-pointers','-o', bitcode_target_name,target_name)
        elsif $compiler_state_env == CompilerState::BaggyNoChecks.value  
          # Baggy no checks
          puts "Baggy no checks"
          run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds',"-baggy-save-local","-dce","-constprop",'-o', bitcode_target_name,target_name)
        elsif  $compiler_state_env == CompilerState::BaggyStackMD.value 
          # Baggy stack MD only -  no checks, no heap (change header) and no globals (Stack md only)
          run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds',"-baggy-save-local","-baggy-globals=false","-dce","-constprop",'-o', bitcode_target_name,target_name)
        end
        # Baggy no checks, no stack, no heap (header and recompiler) and no globals (Only initialization and teardown(*))
        # Heap can be turned off by setting a header and recompiling Baggy
        # run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds',"-baggy-globals=false","-dce","-constprop",'-o', bitcode_target_name,target_name)

        # Debug
        # run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds',"-dce","-constprop",'-o', bitcode_target_name,target_name)

        # Optimize IR as specified
        opt_level = get_optlevel_for_llc(cmd)
        run!(find_opt(),'-dce','-simplifycfg',opt_level,'-o', bitcode_target_name,bitcode_target_name)

        # Step 3 - Instrument the resultant bitcode file for coverage (GCOV)
        if $generate_profiling_info
          gcov_name = mangle(target_name, '.o', '.gcov.o')
          run!(find_opt(),'-insert-gcov-profiling','-o', bitcode_target_name,bitcode_target_name)
        end

        # Step 4 - Covert it into an object file
        opt_level = get_optlevel_for_llc(cmd)
        run!(find_llc(),opt_level, '-filetype=obj', '-relocation-model=pic','-o', target_name, bitcode_target_name)

      rescue RunExternalCommandError
        # Nothing to do...
      end
    end
  end

  def do_link(cmd)
    linker_args = cmd[1..-1]
    if $generate_profiling_info
      linker_args = insert_arg(linker_args, '-coverage')
    end
    # Find baggy rt
    #puts find_baggy_lib()
    linker_args = insert_linker_arg(linker_args, find_baggy_lib())
    linker_args = insert_linker_arg(linker_args,"-lm")
    #puts "Linking",cmd[0], linker_args
    super([cmd[0]] + linker_args)
  end
end


class PlacementCompiler < BaseCompiler
  def do_compile(cmd)
    target_name = get_arg(cmd, '-o')
    clang = find_clang()

    return super unless target_name 

    if target_name 
      begin
        clang_args = cmd[1..-1]
        # The simple one shot process does not work for real apps so keep obj files separately
        clang_args = insert_arg(clang_args, '-flto')
        # clang_args = insert_arg(clang_args, '-emit-llvm')
        if target_name.end_with?('.o')
          bitcode_target_name= mangle(target_name, '.o', '.o.bc')
        elsif target_name.end_with?('.lo')
          bitcode_target_name= mangle(target_name, '.lo', '.lo.bc')
        elsif target_name.end_with?('.la')
          bitcode_target_name= mangle(target_name, '.la', '.la.bc')
        end
        # clang_args.delete('-o')
        # clang_args.delete(target_name)
        # clang_args=["-o "+bitcode_target_name] + clang_args

        # We freeze code at O0 and find the operations to monitor
        optimization_level=clang_args.select { |clang_arg| clang_arg.include?('-O')}
        unless optimization_level.empty?
          optimization_level_arg_pos=clang_args.find_index(optimization_level.first)
          clang_args[optimization_level_arg_pos]='-O0'
          # clang_args = clang_args.insert(optimization_level_arg_pos+1, '-Xclang')
          # clang_args = clang_args.insert(optimization_level_arg_pos+2, '-disable-O0-optnone')
          # clang_args[optimization_level_arg_pos]='-O1'
          # clang_args = clang_args.insert(optimization_level_arg_pos+1, '-Xclang')
          # clang_args = clang_args.insert(optimization_level_arg_pos+2, '-disable-llvm-passes')
        end
        # puts "Placement clang (compile time) args",clang_args
        run!(clang, *clang_args)

        run!(find_opt(), '-load',find_sanitization_helper_pass(),'-pre-sanitize','-o',target_name,target_name)

        # Baggy bounds  
        run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds','-baggy-globals=false','-baggy-save-local', '-baggy-pointers','-o', target_name,target_name)

        # # ASan
        # # run!(find_opt(),'-asan','-asan-module','-asan-globals=false','-o',target_name,target_name)
        run!(find_opt(),'-asan','-asan-module','-asan-globals=false','-asan-precise-stack=true','-o',target_name,target_name)
        # run!(find_opt(),'-asan','-asan-module','-asan-globals=false','-asan-precise-stack=true','-asan-recover=true','-o',target_name,target_name)

        # Post sanitize  
        run!(find_opt(), '-load',find_sanitization_helper_pass(),'-post-sanitize','-dce','-simplifycfg','-o', target_name,target_name)

        opt_level = get_optlevel_for_llc(cmd)
        run!(find_opt(),opt_level,'-o', bitcode_target_name,target_name)

        # Covert it into an object file, bitcode_target_name, opt_level
        opt_level = get_optlevel_for_llc(cmd)
        run!(find_llc(),opt_level,'-optimize-regalloc', '-filetype=obj', '-relocation-model=pic','-o', target_name, bitcode_target_name)

      rescue RunExternalCommandError
        # Nothing to do...
      end
    end
  end

  def do_link(cmd)
    linker_args = cmd[1..-1]
    # Deep copy
    # bitcode_link_args=linker_args.dup
    # bitcode_link_args=bitcode_link_args.select { |link_arg| link_arg.include?('.o') }
    # # Figure out the binary name from the link command
    # binary_name = get_arg(linker_args,'-o')
    # unless binary_name.nil? || binary_name.empty?
    #     bitcode_target_name=binary_name+".bc"
    #     final_object_file_name=binary_name+".o"

    #     # Link all bitcode files
    #     bitcode_link_args=bitcode_link_args.insert(0,find_llvm_link())
    #     bitcode_link_args=bitcode_link_args.insert(1,'-o')
    #     bitcode_link_args=bitcode_link_args.insert(2,bitcode_target_name)
    #     run!(*bitcode_link_args)

    #     # Placement Step 1 - Instrument to guide sanitization
    #     instrumented_bitcode_target_name= mangle(final_object_file_name, '.o', '.pre.bc')
    #     run!(find_opt(), '-load',find_sanitization_helper_pass(),'-pre-sanitize','-o',instrumented_bitcode_target_name,bitcode_target_name)

    #     # Optimize IR as specified 
    #     # opt_level = get_optlevel_for_llc(cmd)
    #     # optimized_placement_target_name=mangle(bitcode_target_name, '.bc', '.opt.bc')
    #     # run!(find_opt(), opt_level,'-o', optimized_placement_target_name,instrumented_bitcode_target_name)

    #     # Step 2 - Instrument the resulting bitcode file with the first monitor - Baggy
    #     run!(find_opt(), '-load',find_baggy_pass_lib(),'-baggy-bounds','-baggy-globals=false','-baggy-save-local', '-baggy-pointers','-o', bitcode_target_name,instrumented_bitcode_target_name)

    #     # Step 3 - Instrument the resulting bitcode file with the second monitor - ASAN
    #     run!(find_opt(),'-asan','-asan-module','-asan-globals=false','-asan-precise-stack=true','-o',bitcode_target_name,bitcode_target_name)

    #     # Step 4 - Run pass to remove checks (and other operations if possible) as needed
    #     # Needs to use actual binary name
    #     placement_target_name=mangle(bitcode_target_name, '.bc', '.placement.bc')
    #     run!(find_opt(), '-load',find_sanitization_helper_pass(),'-post-sanitize','-dce','-simplifycfg','-o', placement_target_name,bitcode_target_name)

    #     # # Optimize IR as specified 
    #     opt_level = get_optlevel_for_llc(cmd)
    #     optimized_placement_target_name=mangle(bitcode_target_name, '.bc', '.opt.bc')
    #     run!(find_opt(), opt_level,'-o', optimized_placement_target_name,placement_target_name)

    #     # Convert the single resultant bitcode file to an optimized object file using LLC
    #     # '-optimize-regalloc'
    #     run!(find_llc(),opt_level, '-optimize-regalloc','-filetype=obj', '-relocation-model=pic','-o', final_object_file_name, optimized_placement_target_name)

    #     #  Link now (Create executable)
    #     object_files=linker_args.select { |link_arg| link_arg.include?('.o')}
    #     first_obj_index=linker_args.find_index(object_files.first)
    #     last_obj_index=linker_args.find_index(object_files.last)

    #     linker_args[first_obj_index]=final_object_file_name
    #     if linker_args[last_obj_index+1..linker_args.length-1]
    #         linker_args=linker_args[0..first_obj_index]+linker_args[last_obj_index+1..linker_args.length-1]
    #     else
    #         linker_args=linker_args[0..first_obj_index]
    #     end
    # else

    #       for obj_file_name in bitcode_link_args do
    #           # Optimize IR as desired (as mentioned in the command)
    #           opt_level = get_optlevel_for_llc(cmd)
    #           run!(find_opt(), opt_level,'-o', obj_file_name,obj_file_name)
    #           # Convert the single resultant bitcode file to an optimized object file using LLC
    #           run!(find_llc(),opt_level, '-filetype=obj', '-relocation-model=pic','-o', obj_file_name, obj_file_name)
    #       end  
    # end        
    # Link baggy rt
    linker_args = insert_linker_arg(linker_args, find_baggy_lib())
    linker_args = insert_linker_arg(linker_args,"-lm")
    linker_args = insert_linker_arg(linker_args,"-fsanitize=address")
    # puts "Linking",cmd[0], linker_args
    super([cmd[0]] + linker_args)
  end

end

# Some makefiles compile and link with a single command. We need to handle this
# specially and convert it into multiple commands.
def handle_compile_and_link(argv)
  source_files = argv.select { |f| f =~ /\.(?:c|cc|C|cxx|cpp)$/ }
  is_compile = get_arg(argv, '-c', :first)
  output_file = get_arg(argv, '-o')
  return false if source_files.empty? or is_compile or not output_file

  # OK, this is a combined compile-and-link.
  # Replace it with multiple commands, where each command compiles a single source file.
  non_source_opts = argv.select { |a| not source_files.include?(a) }
  source_files.each do |f|
    current_args = non_source_opts.collect { |a| if a == output_file then "#{f}.o" else a end }
      current_args += ['-c', f]
      main(current_args)
    end

    # Add a link command
    link_args = argv.collect { |a| if source_files.include?(a) then "#{a}.o" else a end }
      main(link_args)

      return true
end

# Some makefiles compile without specifying -o, relying on compilers to choose
# the name of the object file.
def handle_missing_output_name(argv)
  source_files = argv.select { |f| f =~ /\.(?:c|cc|C|cxx|cpp)$/ }
  is_compile = get_arg(argv, '-c', :first)
  output_file = get_arg(argv, '-o')
  #puts "Missing output name invoked:",argv,output_file,is_compile
  return false if source_files.size != 1 or not is_compile or output_file

  # Add the output name manually. The default compiler behavior is to replace
  # the extension with .o, and place the file in the current working directory.
  output_file = source_files[0].sub(/\.(?:c|cc|C|cxx|cpp)$/, '.o')
  output_file = File.basename(output_file)
  main(argv + ['-o', output_file])
  return true
end

# Some build systems (libtool, I'm looking at you) use -MF and related options.
# We create empty dependency files to make them happy. Note that this is a
# hack... for example, it doesn't handle the case when -M is given without -MF,
# and it will break dependency tracking.
def handle_mf_option(argv)
  is_compile = get_arg(argv, '-c', :first)
  dependency_file = get_arg(argv, '-MF')

  if is_compile and dependency_file
    IO.write(dependency_file, "# Stub dependency file created by asap-clang")
  end

  return false  # continue the compilation anyway
end

#TODO - Deal with transitions or using  compiler setting dynamically later
def main(argv)
  command = get_arg(argv, /^-my-[a-z0-9-]+$/, :first)
  state = AsapState.instance
  $compiler_state_env = CompilerState::BaseMode
  $generate_profiling_info=false

  # Let's determine state using an env 
  if ENV.key?($compiler_state_env_name)
    $compiler_state_env = ENV[$compiler_state_env_name]
    # puts "Compiler status: #{$compiler_state_env}"
  end  

  if ENV.key?($generate_profiling_info_env_name)
    $generate_profiling_info = true
    # puts "Compiler status: #{$compiler_state_env}"
  end  

  case $compiler_state_env 
  when CompilerState::ASanFull.value, CompilerState::ASanNoChecks.value, CompilerState::ASanStackMD.value  
    # puts "ASan build"
    state.transition(:initial, :asan)
  when CompilerState::BaggyFull.value, CompilerState::BaggyNoChecks.value, CompilerState::BaggyStackMD.value  
    # puts "Baggy build"
    state.transition(:initial, :baggy)
  when CompilerState::PlacementMode.value  
    state.transition(:initial, :place)
  else
    # Making optbase default
    # state.transition(:initial, :base)
  end




  if command.nil?
    # We are being run like a regular compilation tool.

    # First, handle a few compiler/makefile quirks
    return if handle_compile_and_link(argv)
    return if handle_missing_output_name(argv)
    return if handle_mf_option(argv)

    # Figure out the right compilation stage, and run the corresponding command.
    # puts "Exec nill command", argv, [$0]
    compiler = state.create_compiler
    compiler.exec([$0] + argv)

  else
    raise "unknown command: #{command}"
  end
end

main(ARGV)














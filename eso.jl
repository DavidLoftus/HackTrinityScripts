module ESO
    import Base: read, show, isvalid, getproperty
    using Printf
	
	export ESOProgram, Section, Instruction
	
	mutable struct Section
		name::String
		nodata::Bool
        data::Vector{UInt8}
        address::UInt32
        offset::Int
	end

	function read(io::IO, ::Type{Section})
		name = readuntil(io, '\0')
		nodata = read(io, UInt8) != 0
		len = read(io, UInt32) |> ntoh
		
		Section(name,nodata,Vector{UInt8}(undef,len), 0, 0)
	end


	struct ESOProgram
		version::UInt16
		start::UInt32
		sections::Dict{Symbol,Section}
	end

    function read(io::IO, ::Type{ESOProgram})
        spos = position(io)

		sig = read(io, 3) |> String
		@assert sig == "ESO"
		
		version = read(io, UInt16) |> ntoh
		@assert version == 1337
		
		start = read(io, UInt32) |> ntoh
		
		nelems = read(io, UInt16)  |> ntoh
		
        sections = [read(io,Section) for i = 1:nelems]
        sz = 0
        for section in sections
            section.address = sz
            sz += length(section.data)
			if !section.nodata
                try
                    section.offset = position(io) - spos
					read!(io,section.data)
				catch e
					if e isa EOFError
						println("Error reading sector $(section.name)")
						break
					end
					rethrow()
				end
            end
		end
		
		ESOProgram(version, start, Dict(Symbol(section.name[2:end]) => section for section in sections))
    end
    
    function getproperty(eso::ESOProgram, symb::Symbol)
        sections = getfield(eso, :sections)
        if haskey(sections, symb)
            return sections[symb]
        else
            return getfield(eso,symb)
        end
    end

    @enum OpCode begin
        NOP = 0
        MOV
        ADD
        SUB
        BOR
        AND
        XOR
        SHL
        SHR
        CMP
        LDR
        STR
        JMP
        SYS
        INVALID1
        INVALID2
    end

    const IMMEDIATE = 1
    const MODE = 6
    const CALL = 8

    struct Instruction
        opcode::OpCode
        flags::UInt8
        reg::UInt8
        operand::UInt32
    end

    const RegisterNames = [ "eax", "ebx", "ecx", "edx", "r0", "r1", "r2", "r3", "r4", "pc", "esp", "ret", "rF" ]
    const AddressSizes = [ "b", "w", "dw" ]
    const JumpTypes = [ "", "Z", "NZ"]

    _tostring(x::Integer) = (x > 255) ? "0x"*string(x, base=16) : string(x)

    function convert_vaddr(eso::ESOProgram, addr::UInt32)
        for (k,v) in eso.sections
            if addr in range(v.address, length=length(v.data))
                return v.name => addr - v.address
            end
        end
        @error "Address $addr is not in any sections"
    end

    function show(io::IO, inst::Instruction)

        operand = (inst.flags & IMMEDIATE == IMMEDIATE) ? _tostring(inst.operand) : RegisterNames[inst.operand+1]

        mode = (inst.flags & MODE) >> 1 + 1

        if inst.opcode == JMP
            if operand == "ret"
                print(io, "RET")
            else
                opcode = (inst.flags & CALL == CALL) ? "CALL" : "JMP"

                print(io, "$opcode $(JumpTypes[mode]) $operand")
            end
        elseif inst.opcode == SYS
            print(io, "SYSCALL $(RegisterNames[inst.reg+1]), $operand")
        else
            print(io, inst.opcode)

            if MOV <= inst.opcode <= CMP
                print(io, " $(RegisterNames[inst.reg+1]), $operand")
            elseif LDR <= inst.opcode <= STR
                print(io, " $(RegisterNames[inst.reg+1]), $(AddressSizes[mode]):[$operand]")
            end
        end
    end

    function isvalid(inst::Instruction)
        if inst.opcode > SYS
            return false
        end

        if inst.reg == 9 || inst.reg > 11
            return false
        end

        if inst.flags & IMMEDIATE == 0 && inst.operand > 12
            return false
        end

        return true
    end

    function dumpcode(eso::ESOProgram)
        section = eso.text
        offset = section.address
        buf = IOBuffer(section.data)

        while !eof(buf)
            inst = read(buf, Instruction)
            addr = string(position(buf)+offset,base=16,pad=8)
            extrainfo = if !isvalid(inst)
                "INVALID"
            elseif LDR <= inst.opcode <= JMP && inst.flags & IMMEDIATE != 0
                _section,_offset = convert_vaddr(eso,inst.operand)
                "; $_section:$(string(inst.operand,base=16,pad=8))"
            else
                ""
            end
            println("$(section.name):$addr\t$inst\t$extrainfo")
        end
    end

    function read(io::IO, ::Type{Instruction})
        inst1 = read(io, UInt16) |> ntoh
        opcode = inst1 >> 12
        flags = (inst1 >> 4) & 255
        reg = inst1 & 15
        operand = read(io, UInt32) |> ntoh

        Instruction(OpCode(opcode), flags, reg, operand)
    end
	
	function crack(eso::ESOProgram, key::Vector{Char} = collect("XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX"))
		if !haskey(eso.sections,:s_offset)
			return eso, key
		end
		
		keyOffset = reinterpret(UInt32, eso.sections.s_offset)[1] |> ntoh
		
		data = eso.data
		
		key = xor(data[1],UInt8('E')) # We know first 3 bytes are ESO
		
		data = xor.(data, key)
		
		io = IOBuffer(data)
		
		eso2 = read(io, ESOProgram)
		
		return crack(eso2, key)
	end

end
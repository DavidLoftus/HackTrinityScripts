
ENV["LD_LIBRARY_PATH"] = pwd()


function rc4_encrypt(input::Vector{UInt8}, key::String, output = Vector{UInt8}(undef, length(input)))
    ccall((:rc4_encrypt,"librc4"), Int32, (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Cstring), output, input, length(input), key)
    return output
end

function finddata(file)
    start,size,name = nothing,nothing,nothing
    open(`nm --defined-only $file`) do io
        for line in eachline(io)
            val, _, symbol = split(line)
            m = match(r"_binary_(.*?)_(start|size)",symbol)
            if m !== nothing
                val = parse(UInt64, val, base=16)
                name = m.captures[1]
                if m.captures[2] == "start"
                    start = val
                else
                    size = val
                end
            end
        end 
    end
    start,size,name
end

function bruteforce(data, key)

    i = findfirst(isequal('0'), key)

    key1,key2 = key[1:i-1],key[i+2:end]

    output = Vector{UInt8}(undef, length(data))
    cracked = false

    for c1 = 'A':'Z', c2 = 'A':'Z'
        key = "$key1$c1$c2$key2"
        rc4_encrypt(data,key,output)

        if output[1] == 127 && output[2] == 69 && output[3] == 76 && output[4] == 70
            cracked = true
            break
        end
    end

    @assert cracked "Failed to crack layer, key = $key"

    output,key
end

function cracklayer(file, key = "000000-000000-000000-000000-000000")
    # Find data offset for next layer
    
    start,size,name = finddata(file)
    if start === nothing || size == nothing
        return key, nothing
    end
    
    # Extract data
    data = open(file) do f
        seek(f, start)
        read(f, size)
    end

    output,key = bruteforce(data, key)

    file2 = "$name.so"
    write(file2, output)

    file2, key
end

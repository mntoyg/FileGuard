
            #!/bin/bash
            clear  # Clear the terminal screen at the start
            cd "c:\Users\Thanapat Manasom\Desktop\FileGuard\FileGuard\src"
            if [ -f main ]; then
                rm main  # Remove the old binary if it exists
            fi
            g++ -o main main.cpp
            if [ $? -eq 0 ]; then
                ./main
            else
                echo "Compilation failed."
            fi
            echo ""  # Add a newline for better separation
            rm "c:\Users\Thanapat Manasom\Desktop\FileGuard\FileGuard\src\.main_run.sh"
        
echo "[X] Entering target's build dir: $TARGET_DIR/build/gmake"
cd $TARGET_DIR/build/gmake
make clean 
echo "[X] Starting compilation"
echo "Running command make"
make
# This below step is only necessary in case the target does not
# have standard `configure` to specify build prefix
echo "[X] Copying binary to its dedicated location"
cp $TARGET_DIR/bin/tidy $PREFIX/ 

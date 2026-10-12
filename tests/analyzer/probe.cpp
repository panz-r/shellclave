int analyzer_cpp_probe() {
  int value = 7;
  int *pointer = &value;
#if ANALYZER_DEFECT
  pointer = nullptr;
#endif
  return *pointer;
}

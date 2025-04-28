@echo off
echo ============================================
echo Ejecutando prueba con 4 clientes...
echo ============================================
java ClienteConcurrente > resultados_4_clientes.txt

echo ============================================
echo Ejecutando prueba con 16 clientes...
echo ============================================
set NUM_CLIENTES=16
java ClienteConcurrente > resultados_16_clientes.txt

echo ============================================
echo Ejecutando prueba con 32 clientes...
echo ============================================
set NUM_CLIENTES=32
java ClienteConcurrente > resultados_32_clientes.txt

echo ============================================
echo Ejecutando prueba con 64 clientes...
echo ============================================
set NUM_CLIENTES=64
java ClienteConcurrente > resultados_64_clientes.txt

echo ============================================
echo Todas las pruebas finalizadas.
pause
